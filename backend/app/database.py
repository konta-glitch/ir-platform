"""
Database — SQLite persistence for incidents and agent data.

Local-first: a single SQLite file under /app/data so incidents survive
restarts. We store each Incident as JSON (the Pydantic model serializes
cleanly) plus the agent's full investigation data blob, keyed by incident_id.

Design notes:
  - SQLite is ideal here: no server, file-based, ACID, ships with Python.
  - We keep the schema deliberately simple (document-style) so model changes
    don't require migrations — the JSON column absorbs new fields.
  - The agent_data blob can be large (full parsed artifacts), so it lives in
    its own table and is loaded only when an investigation runs.
  - All writes are synchronous SQLite calls; callers run them in a thread
    (via asyncio.to_thread) where they're on the async path, to avoid
    blocking the event loop.
"""

import json
import logging
import sqlite3
import threading
from pathlib import Path
from datetime import datetime
from typing import Any, Optional

import os

logger = logging.getLogger(__name__)

# DB path: /app/data in the container, overridable for local/testing
DB_PATH = Path(os.environ.get("IR_DB_PATH", "/app/data/ir_platform.db"))


class Database:
    """Thread-safe SQLite store for incidents and investigation data."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + a lock lets us share one connection across
        # the thread-pool workers that asyncio.to_thread uses.
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()
        logger.info(f"Database ready at {self.db_path}")

    def _init_schema(self):
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS incidents (
                    id          TEXT PRIMARY KEY,
                    title       TEXT,
                    status      TEXT,
                    severity    TEXT,
                    created_at  TEXT,
                    updated_at  TEXT,
                    data        TEXT NOT NULL          -- full Incident as JSON
                );

                CREATE TABLE IF NOT EXISTS agent_data (
                    incident_id TEXT PRIMARY KEY,
                    data        TEXT NOT NULL,          -- structured_data + results JSON
                    created_at  TEXT,
                    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_incidents_updated
                    ON incidents(updated_at DESC);
            """)
            self._conn.commit()

    # ── Incidents ──

    def save_incident(self, incident_id: str, incident_json: dict,
                      title: str, status: str, severity: str,
                      created_at: str, updated_at: str):
        """Insert or update an incident (full document upsert)."""
        with self._lock:
            self._conn.execute("""
                INSERT INTO incidents (id, title, status, severity, created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    title=excluded.title, status=excluded.status,
                    severity=excluded.severity, updated_at=excluded.updated_at,
                    data=excluded.data
            """, (incident_id, title, status, severity, created_at, updated_at,
                  json.dumps(incident_json, default=str)))
            self._conn.commit()

    def get_incident(self, incident_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
        return json.loads(row["data"]) if row else None

    def list_incidents(self) -> list[dict]:
        """Return all incidents as JSON dicts, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT data FROM incidents ORDER BY updated_at DESC"
            ).fetchall()
        return [json.loads(r["data"]) for r in rows]

    def delete_incident(self, incident_id: str):
        with self._lock:
            self._conn.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
            self._conn.execute("DELETE FROM agent_data WHERE incident_id = ?", (incident_id,))
            self._conn.commit()

    def count_incidents(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT COUNT(*) AS c FROM incidents").fetchone()
        return row["c"] if row else 0

    # ── Agent data (large blobs, loaded on demand) ──

    def save_agent_data(self, incident_id: str, agent_data: dict):
        """Persist the full structured data + results for the investigation agent.

        The blob can be very large (every parsed artifact row from a 60GB
        collection). We gzip the JSON before storing — forensic JSON compresses
        ~10-20x — so it comfortably fits where the raw text would blow past
        SQLite's blob limit ("string or blob too big"). Stored as a BLOB.
        """
        import gzip
        raw = json.dumps(agent_data, default=str).encode("utf-8")
        compressed = gzip.compress(raw, compresslevel=6)
        logger.info(
            f"Agent data for {incident_id}: {len(raw)/1e6:.1f}MB → "
            f"{len(compressed)/1e6:.1f}MB compressed"
        )
        with self._lock:
            self._conn.execute("""
                INSERT INTO agent_data (incident_id, data, created_at)
                VALUES (?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET data=excluded.data
            """, (incident_id, compressed, datetime.utcnow().isoformat()))
            self._conn.commit()

    def get_agent_data(self, incident_id: str) -> Optional[dict]:
        import gzip
        with self._lock:
            row = self._conn.execute(
                "SELECT data FROM agent_data WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        if not row:
            return None
        blob = row["data"]
        # New rows are gzip BLOBs; tolerate any legacy plain-JSON TEXT rows.
        if isinstance(blob, (bytes, bytearray)):
            try:
                return json.loads(gzip.decompress(blob).decode("utf-8"))
            except (OSError, gzip.BadGzipFile):
                return json.loads(bytes(blob).decode("utf-8"))
        return json.loads(blob)

    def close(self):
        with self._lock:
            self._conn.close()


# Global singleton
_db: Optional[Database] = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
