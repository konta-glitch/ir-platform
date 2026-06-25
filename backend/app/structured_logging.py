"""
Structured logging — audit trail + debug tracing.

Two complementary logs:

  1. AUDIT LOG (audit.jsonl) — one JSON line per significant event:
     analysis started/completed, escalations, rule loads, errors.
     Answers "who/what/when" for every action. Survives restarts.

  2. DEBUG TRACE — verbose step-by-step pipeline logging to stdout
     (and optionally a file) when LOG_LEVEL=DEBUG. Every parsing step,
     every detection rule batch, every LLM call with timing.

The audit log is append-only JSONL so it can be grepped, tailed, or
ingested into a SIEM. Each record has a stable schema.
"""

import json
import logging
import time
import uuid
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Any

# ── Audit log ──

AUDIT_PATH = Path("/app/data/audit.jsonl")


class AuditLogger:
    """Append-only structured audit log (JSONL)."""

    def __init__(self, path: Path = AUDIT_PATH):
        self.path = path
        # NOTE: do NOT create the directory here. This class is instantiated at
        # import time (module-level _audit), and importing a module must not
        # touch the filesystem — in CI (no /app dir, no root write access) that
        # raised PermissionError and broke `import app.main`. The directory is
        # created lazily on first write instead.
        self._dir_ready = False

    def _ensure_dir(self) -> bool:
        """Create the log directory on first use. Returns False if it can't."""
        if self._dir_ready:
            return True
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._dir_ready = True
        except Exception as e:
            logging.getLogger(__name__).warning(f"Audit dir unavailable: {e}")
            return False
        return True

    def record(self, event_type: str, **fields: Any) -> str:
        """Write one audit record. Returns the record's unique id."""
        record_id = str(uuid.uuid4())[:12]
        entry = {
            "id": record_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            **fields,
        }
        if not self._ensure_dir():
            return record_id  # degrade gracefully — no audit dir available
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            logging.getLogger(__name__).warning(f"Audit write failed: {e}")
        return record_id

    def read_recent(self, limit: int = 100,
                    event_filter: str | None = None) -> list[dict]:
        """Read recent audit records, newest first."""
        if not self.path.exists():
            return []
        records = []
        try:
            with open(self.path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                        if event_filter and rec.get("event") != event_filter:
                            continue
                        records.append(rec)
                    except json.JSONDecodeError:
                        continue
        except Exception:
            pass
        return list(reversed(records))[:limit]

    def stats(self) -> dict:
        """Summary statistics of the audit log."""
        if not self.path.exists():
            return {"total_events": 0}
        counts: dict[str, int] = {}
        total = 0
        try:
            with open(self.path) as f:
                for line in f:
                    if line.strip():
                        try:
                            ev = json.loads(line).get("event", "unknown")
                            counts[ev] = counts.get(ev, 0) + 1
                            total += 1
                        except json.JSONDecodeError:
                            continue
        except Exception:
            pass
        return {"total_events": total, "by_type": counts}


# ── Debug trace ──

class PipelineTracer:
    """
    Verbose step tracing for a single analysis run.

    Usage:
        tracer = PipelineTracer(logger, trace_id="abc123")
        tracer.note("Dataset loaded")
        with tracer.stage("detection_engine", rows=5000) as st:
            ...
            st["metrics"]["findings"] = 42

    Each stage records timing automatically and emits DEBUG logs.
    """

    def __init__(self, logger: logging.Logger, trace_id: str | None = None):
        self.logger = logger
        self.trace_id = trace_id or str(uuid.uuid4())[:8]
        self.stages: list[dict] = []
        self.notes: list[dict] = []
        self._start = time.time()

    def note(self, message: str, **detail: Any):
        """Record a free-form note (not a timed stage)."""
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "message": message,
            "elapsed_total_s": round(time.time() - self._start, 3),
            **detail,
        }
        self.notes.append(entry)
        self.logger.debug(f"[{self.trace_id}] NOTE: {message}")

    @contextmanager
    def stage(self, name: str, **context: Any):
        """
        Context manager for a timed pipeline stage.
        Yields a mutable dict; populate stage['metrics'][...] inside.
        """
        stage_record = {
            "stage": name,
            "context": context,
            "metrics": {},
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        ctx_str = " ".join(f"{k}={v}" for k, v in context.items())
        self.logger.debug(f"[{self.trace_id}] ▶ {name} start {ctx_str}")
        start = time.time()
        error = None
        try:
            yield stage_record
        except Exception as e:
            error = str(e)
            stage_record["error"] = error
            raise
        finally:
            duration = round(time.time() - start, 3)
            stage_record["duration_s"] = duration
            self.stages.append(stage_record)
            metrics_str = " ".join(f"{k}={v}" for k, v in stage_record["metrics"].items())
            status = "✗" if error else "✓"
            self.logger.debug(
                f"[{self.trace_id}] {status} {name} done in {duration}s {metrics_str}"
            )

    def summary(self) -> dict:
        """Return the full trace for inclusion in a report."""
        return {
            "trace_id": self.trace_id,
            "total_duration_s": round(time.time() - self._start, 3),
            "stage_count": len(self.stages),
            "stages": [
                {
                    "stage": s["stage"],
                    "duration_s": s.get("duration_s", 0),
                    "metrics": s.get("metrics", {}),
                    "error": s.get("error"),
                }
                for s in self.stages
            ],
            "notes": self.notes,
        }


def get_audit_logger() -> AuditLogger:
    """Alias for compatibility."""
    return _audit


# ── Global instances + setup ──

_audit = AuditLogger()


def get_audit() -> AuditLogger:
    return _audit


def configure_logging(level: str = "INFO"):
    """Configure root logging with a consistent format."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        force=True,
    )
    # Quiet noisy libraries unless we're debugging
    if log_level > logging.DEBUG:
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)


def setup_logging(log_level: str = "INFO"):
    """Alias for configure_logging (compat)."""
    configure_logging(log_level)


@contextmanager
def trace_run(logger: logging.Logger, run_id: str | None = None):
    """Context manager yielding a PipelineTracer for one analysis run."""
    rid = run_id or str(uuid.uuid4())[:8]
    tracer = PipelineTracer(rid, logger)
    try:
        yield tracer
    finally:
        logger.debug(f"[{rid}] trace complete: {len(tracer.steps)} steps, "
                     f"{tracer.summary()['total_duration_s']}s total")
