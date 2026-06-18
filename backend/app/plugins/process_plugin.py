"""
Built-in analyzer plugins.

Each plugin normalises one category of forensic data into Artifact objects.
The detection engine, correlation engine, and Sigma rules all consume Artifacts —
plugins are the only layer that knows about raw collection formats.
"""

from __future__ import annotations
import uuid
import logging
from typing import Any

from app.models import Artifact, ArtifactType
from app.plugins import AnalyzerPlugin

logger = logging.getLogger(__name__)


def _new_id() -> str:
    return str(uuid.uuid4())[:8]


# ── Process plugin ────────────────────────────────────────────────────────────

class ProcessPlugin(AnalyzerPlugin):
    name    = "process_plugin"
    version = "1.0.0"

    _KEYS = {"processes", "process_list", "running_processes", "ProcessList", "Process"}

    def can_handle(self, key: str, data: Any) -> bool:
        return key in self._KEYS and isinstance(data, list)

    def analyze(self, key: str, data: list[dict]) -> list[Artifact]:
        out = []
        for row in data:
            if not isinstance(row, dict):
                continue
            ts = (row.get("TimeCreated") or row.get("timestamp") or
                  row.get("create_time") or "")
            out.append(Artifact(
                id      = _new_id(),
                type    = ArtifactType.PROCESS,
                source  = key,
                timestamp = str(ts),
                host    = str(row.get("host") or row.get("Computer") or ""),
                attributes = row,
                collector_version = self.version,
            ))
        return out


# ── Network plugin ────────────────────────────────────────────────────────────

class NetworkPlugin(AnalyzerPlugin):
    name    = "network_plugin"
    version = "1.0.0"

    _KEYS = {"network", "connections", "network_connections", "NetworkConnections",
             "dns", "dns_cache", "arp"}

    def can_handle(self, key: str, data: Any) -> bool:
        return key in self._KEYS and isinstance(data, list)

    def analyze(self, key: str, data: list[dict]) -> list[Artifact]:
        out = []
        for row in data:
            if not isinstance(row, dict):
                continue
            ts = row.get("timestamp") or row.get("TimeCreated") or ""
            out.append(Artifact(
                id        = _new_id(),
                type      = ArtifactType.NETWORK,
                source    = key,
                timestamp = str(ts),
                host      = str(row.get("host") or ""),
                attributes = row,
                collector_version = self.version,
            ))
        return out


# ── Event log plugin ──────────────────────────────────────────────────────────

class EventLogPlugin(AnalyzerPlugin):
    name    = "eventlog_plugin"
    version = "1.0.0"

    _KEYS = {"eventlog", "events", "event_logs", "EventLog", "windows_events",
             "security_events", "system_events", "application_events"}

    def can_handle(self, key: str, data: Any) -> bool:
        return key in self._KEYS and isinstance(data, list)

    def analyze(self, key: str, data: list[dict]) -> list[Artifact]:
        out = []
        for row in data:
            if not isinstance(row, dict):
                continue
            ts = (row.get("TimeCreated") or row.get("timestamp") or
                  row.get("EventTime") or "")
            out.append(Artifact(
                id        = _new_id(),
                type      = ArtifactType.EVENT,
                source    = key,
                timestamp = str(ts),
                host      = str(row.get("Computer") or row.get("host") or ""),
                attributes = row,
                collector_version = self.version,
            ))
        return out


# ── Persistence plugin ────────────────────────────────────────────────────────

class PersistencePlugin(AnalyzerPlugin):
    name    = "persistence_plugin"
    version = "1.0.0"

    _KEYS = {"persistence", "scheduled_tasks", "services", "startup", "registry",
             "autorun", "Tasks", "Services", "RunKeys"}

    def can_handle(self, key: str, data: Any) -> bool:
        return key in self._KEYS and isinstance(data, list)

    def analyze(self, key: str, data: list[dict]) -> list[Artifact]:
        # Determine sub-type from key name
        if "task" in key.lower():
            atype = ArtifactType.TASK
        elif "service" in key.lower():
            atype = ArtifactType.SERVICE
        elif "registry" in key.lower() or "run" in key.lower():
            atype = ArtifactType.REGISTRY
        else:
            atype = ArtifactType.UNKNOWN

        out = []
        for row in data:
            if not isinstance(row, dict):
                continue
            ts = row.get("timestamp") or row.get("LastRunTime") or ""
            out.append(Artifact(
                id        = _new_id(),
                type      = atype,
                source    = key,
                timestamp = str(ts),
                host      = str(row.get("host") or ""),
                attributes = row,
                collector_version = self.version,
            ))
        return out


# ── Filesystem plugin ─────────────────────────────────────────────────────────

class FileSystemPlugin(AnalyzerPlugin):
    name    = "filesystem_plugin"
    version = "1.1.0"

    _KEYS = {"filesystem", "files", "file_list", "recent_files", "prefetch",
             "Prefetch", "MFT", "mft", "FileSystem",
             # Execution/access evidence artifacts (Shimcache, UserAssist,
             # Shellbags) — same plugin since they're all file-path-centric
             # evidence, but routed to their own detection_engine branches.
             "shimcache", "appcompatcache", "userassist", "shellbags",
             "recyclebin"}

    def can_handle(self, key: str, data: Any) -> bool:
        return key in self._KEYS and isinstance(data, list)

    def analyze(self, key: str, data: list[dict]) -> list[Artifact]:
        key_lower = key.lower()
        if "prefetch" in key_lower:
            atype = ArtifactType.PREFETCH
        elif "mft" in key_lower:
            atype = ArtifactType.MFT
        elif "shimcache" in key_lower or "appcompatcache" in key_lower:
            atype = ArtifactType.UNKNOWN  # execution evidence, not a file write
        elif "userassist" in key_lower:
            atype = ArtifactType.UNKNOWN  # GUI execution evidence
        elif "shellbag" in key_lower:
            atype = ArtifactType.UNKNOWN  # navigation evidence, not a file
        else:
            atype = ArtifactType.FILE
        out = []
        for row in data:
            if not isinstance(row, dict):
                continue
            ts = (row.get("Mtime") or row.get("modified") or
                  row.get("timestamp") or row.get("last_execution") or
                  row.get("last_modified") or row.get("last_executed") or
                  row.get("last_accessed") or "")
            out.append(Artifact(
                id        = _new_id(),
                type      = atype,
                source    = key,
                timestamp = str(ts),
                host      = str(row.get("host") or ""),
                attributes = row,
                collector_version = self.version,
            ))
        return out