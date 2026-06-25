"""
Disk Image Analyzer — extracts IR artifacts from forensic disk images.

Supports: E01 (FTK Imager/EnCase), raw/dd, VMDK, VHD
Uses the dissect framework for image parsing.

Two modes:
  1. Upload: small images via browser upload
  2. Path: large images placed in /app/images volume

Extracts:
  - Registry hives → users, autoruns, services, installed software
  - Event logs → security, system, powershell, sysmon
  - Prefetch → execution evidence
  - Filesystem timeline → recently modified files
  - Scheduled tasks, browser history, network config
"""

import json
import logging
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


def _safe_str(val: Any) -> str:
    """Convert any value to a safe string."""
    if val is None:
        return ""
    try:
        if hasattr(val, 'isoformat'):
            return val.isoformat()
        return str(val)
    except Exception:
        return ""


class ImageAnalyzer:
    """Analyzes forensic disk images using the dissect framework."""

    def __init__(self):
        self.images_dir = Path("/app/images")
        # Don't hard-fail at import (main.py builds this at module level). On a
        # bare CI runner /app isn't writable; degrade by skipping dir creation.
        # The container has the volume mounted, so behaviour there is unchanged.
        try:
            self.images_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logging.getLogger(__name__).warning(
                f"Images dir {self.images_dir} unavailable ({e})"
            )

    def list_available_images(self) -> list[dict]:
        """List images available in the /app/images volume."""
        images = []
        if self.images_dir.exists():
            for f in self.images_dir.iterdir():
                if f.suffix.lower() in ('.e01', '.ex01', '.raw', '.dd', '.img',
                                         '.vmdk', '.vhd', '.vhdx', '.ad1'):
                    images.append({
                        "filename": f.name,
                        "path": str(f),
                        "size_gb": round(f.stat().st_size / (1024**3), 2),
                        "format": f.suffix.lower().lstrip('.'),
                        "modified": datetime.fromtimestamp(
                            f.stat().st_mtime, tz=timezone.utc
                        ).isoformat(),
                    })
        # Also check for split E01 (only show the .E01, not .E02, .E03...)
        seen = set()
        deduped = []
        for img in images:
            base = img["filename"].rsplit('.', 1)[0]
            if base not in seen:
                seen.add(base)
                deduped.append(img)
        return deduped

    async def analyze_image(self, image_path: str,
                             artifacts: list[str] | None = None) -> dict:
        """
        Analyze a disk image and extract forensic artifacts.

        Args:
            image_path: Path to the image file (E01, raw, VMDK, etc.)
            artifacts: List of artifact types to extract. None = all.
                       Options: registry, eventlogs, prefetch, tasks,
                                users, services, autoruns, timeline, browser

        Returns:
            Dict with extracted artifact data as JSON-serializable structures.
        """
        path = Path(image_path)
        if not path.exists():
            return {"error": f"Image not found: {image_path}"}

        if artifacts is None:
            artifacts = [
                "registry", "eventlogs", "prefetch", "tasks",
                "users", "services", "autoruns", "timeline", "browser",
                "amcache", "shimcache", "userassist", "recyclebin", "shellbags",
            ]

        logger.info(f"Analyzing image: {path.name} ({path.stat().st_size / 1e9:.1f}GB)")
        logger.info(f"Artifacts to extract: {artifacts}")

        try:
            from dissect.target import Target
        except ImportError:
            return {"error": "dissect framework not installed. Run: pip install dissect.target"}

        results: dict[str, Any] = {
            "image_info": {
                "filename": path.name,
                "size_gb": round(path.stat().st_size / (1024**3), 2),
                "format": path.suffix.lower().lstrip('.'),
                "analysis_time": datetime.now(timezone.utc).isoformat(),
            },
        }

        try:
            target = Target.open(str(path))
            logger.info(f"Image opened: OS={target.os}, hostname={target._os_plugin.hostname if hasattr(target, '_os_plugin') else 'unknown'}")

            # System info
            results["system_info"] = self._extract_system_info(target)

            # Extract requested artifacts
            for artifact in artifacts:
                try:
                    logger.info(f"  Extracting: {artifact}")
                    if artifact == "users":
                        results["users"] = self._extract_users(target)
                    elif artifact == "services":
                        results["services"] = self._extract_services(target)
                    elif artifact == "autoruns":
                        results["autoruns"] = self._extract_autoruns(target)
                    elif artifact == "eventlogs":
                        results["eventlogs"] = self._extract_eventlogs(target)
                    elif artifact == "prefetch":
                        results["prefetch"] = self._extract_prefetch(target)
                    elif artifact == "tasks":
                        results["tasks"] = self._extract_tasks(target)
                    elif artifact == "timeline":
                        results["timeline"] = self._extract_timeline(target)
                    elif artifact == "browser":
                        results["browser"] = self._extract_browser(target)
                    elif artifact == "registry":
                        results["registry_autoruns"] = self._extract_registry_autoruns(target)
                    elif artifact == "amcache":
                        results["amcache"] = self._extract_amcache(target)
                    elif artifact == "shimcache":
                        results["shimcache"] = self._extract_shimcache(target)
                    elif artifact == "userassist":
                        results["userassist"] = self._extract_userassist(target)
                    elif artifact == "recyclebin":
                        results["recyclebin"] = self._extract_recyclebin(target)
                    elif artifact == "shellbags":
                        results["shellbags"] = self._extract_shellbags(target)
                except Exception as e:
                    logger.warning(f"  Failed to extract {artifact}: {e}")
                    results[artifact] = {"error": str(e)}

        except Exception as e:
            logger.error(f"Failed to open image: {e}")
            results["error"] = f"Failed to open image: {e}"

        # Count total items
        total = sum(
            len(v) if isinstance(v, list) else 1
            for k, v in results.items()
            if k not in ("image_info", "system_info", "error")
        )
        results["image_info"]["total_artifacts_extracted"] = total
        logger.info(f"Extraction complete: {total} artifacts")

        return results

    def _extract_system_info(self, target) -> dict:
        info = {}
        try:
            info["os"] = _safe_str(target.os)
            if hasattr(target, '_os_plugin'):
                p = target._os_plugin
                info["hostname"] = _safe_str(getattr(p, 'hostname', ''))
                info["domain"] = _safe_str(getattr(p, 'domain', ''))
                info["version"] = _safe_str(getattr(p, 'version', ''))
        except Exception as e:
            info["error"] = str(e)
        return info

    def _extract_users(self, target) -> list[dict]:
        users = []
        try:
            for user in target.users():
                users.append({
                    "name": _safe_str(getattr(user, 'user', '')),
                    "sid": _safe_str(getattr(user, 'sid', '')),
                    "home": _safe_str(getattr(user, 'home', '')),
                })
        except Exception as e:
            logger.warning(f"Users extraction: {e}")
        return users[:200]

    def _extract_services(self, target) -> list[dict]:
        services = []
        try:
            for svc in target.services():
                services.append({
                    "name": _safe_str(getattr(svc, 'name', '')),
                    "display_name": _safe_str(getattr(svc, 'display_name', '')),
                    "image_path": _safe_str(getattr(svc, 'image_path', '')),
                    "start_type": _safe_str(getattr(svc, 'start_type', '')),
                    "type": _safe_str(getattr(svc, 'type', '')),
                })
        except Exception as e:
            logger.warning(f"Services extraction: {e}")
        return services[:500]

    def _extract_autoruns(self, target) -> list[dict]:
        autoruns = []
        try:
            for entry in target.autoruns():
                autoruns.append({
                    "name": _safe_str(getattr(entry, 'name', '')),
                    "type": _safe_str(getattr(entry, 'type', '')),
                    "path": _safe_str(getattr(entry, 'path', '')),
                    "value": _safe_str(getattr(entry, 'value', '')),
                    "source": _safe_str(getattr(entry, 'source', '')),
                })
        except Exception as e:
            logger.warning(f"Autoruns extraction: {e}")
        return autoruns[:500]

    def _extract_eventlogs(self, target) -> list[dict]:
        events = []
        interesting_ids = {
            4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720,
            4728, 4732, 4756, 7045, 7040, 1102,  # Security
            4103, 4104,  # PowerShell
            1, 3, 5, 7, 8, 11, 12, 13, 15, 22, 23, 25,  # Sysmon
        }
        try:
            for record in target.evtx():
                eid = getattr(record, 'EventID', None)
                if eid and int(eid) in interesting_ids:
                    events.append({
                        "timestamp": _safe_str(getattr(record, 'TimeCreated', '')),
                        "event_id": int(eid),
                        "channel": _safe_str(getattr(record, 'Channel', '')),
                        "computer": _safe_str(getattr(record, 'Computer', '')),
                        "provider": _safe_str(getattr(record, 'Provider_Name', '')),
                        "data": _safe_str(record)[:800],
                    })
                if len(events) >= 5000:
                    break
        except Exception as e:
            logger.warning(f"Eventlog extraction: {e}")
        return events

    def _extract_prefetch(self, target) -> list[dict]:
        prefetch = []
        try:
            for pf in target.prefetch():
                prefetch.append({
                    "executable": _safe_str(getattr(pf, 'filename', '')),
                    "run_count": getattr(pf, 'run_count', 0),
                    "last_run": _safe_str(getattr(pf, 'last_run', '')),
                    "path": _safe_str(getattr(pf, 'path', '')),
                })
        except Exception as e:
            logger.warning(f"Prefetch extraction: {e}")
        return prefetch[:500]

    def _extract_tasks(self, target) -> list[dict]:
        tasks = []
        try:
            for task in target.tasks():
                tasks.append({
                    "name": _safe_str(getattr(task, 'name', '')),
                    "path": _safe_str(getattr(task, 'path', '')),
                    "command": _safe_str(getattr(task, 'command', '')),
                    "args": _safe_str(getattr(task, 'args', '')),
                    "author": _safe_str(getattr(task, 'author', '')),
                    "enabled": getattr(task, 'enabled', None),
                })
        except Exception as e:
            logger.warning(f"Tasks extraction: {e}")
        return tasks[:200]

    def _extract_timeline(self, target) -> list[dict]:
        """Extract recently modified files from the filesystem."""
        entries = []
        try:
            # Walk suspicious directories
            suspect_paths = [
                "windows/temp", "windows/system32/tasks",
                "users/*/appdata", "users/*/downloads",
                "users/*/desktop", "programdata",
                "tmp", "var/tmp", "home",
            ]
            for spath in suspect_paths:
                try:
                    for entry in target.fs.path(spath).rglob("*"):
                        if entry.is_file():
                            try:
                                stat = entry.stat()
                                entries.append({
                                    "path": str(entry),
                                    "size": stat.st_size if hasattr(stat, 'st_size') else 0,
                                    "modified": _safe_str(datetime.fromtimestamp(
                                        stat.st_mtime, tz=timezone.utc
                                    )) if hasattr(stat, 'st_mtime') else "",
                                    "created": _safe_str(datetime.fromtimestamp(
                                        stat.st_ctime, tz=timezone.utc
                                    )) if hasattr(stat, 'st_ctime') else "",
                                })
                            except Exception:
                                continue
                        if len(entries) >= 2000:
                            break
                except Exception:
                    continue
                if len(entries) >= 2000:
                    break
        except Exception as e:
            logger.warning(f"Timeline extraction: {e}")

        # Sort by modified time, most recent first
        entries.sort(key=lambda x: x.get("modified", ""), reverse=True)
        return entries[:1000]

    def _extract_browser(self, target) -> list[dict]:
        history = []
        try:
            for entry in target.browser_history():
                history.append({
                    "browser": _safe_str(getattr(entry, 'browser', '')),
                    "url": _safe_str(getattr(entry, 'url', '')),
                    "title": _safe_str(getattr(entry, 'title', '')),
                    "visit_time": _safe_str(getattr(entry, 'ts', '')),
                })
                if len(history) >= 1000:
                    break
        except Exception as e:
            logger.warning(f"Browser extraction: {e}")
        return history

    def _extract_registry_autoruns(self, target) -> list[dict]:
        """Extract autorun entries from registry hives."""
        entries = []
        autorun_keys = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        ]
        try:
            for key_path in autorun_keys:
                try:
                    key = target.registry.key(key_path)
                    for value in key.values():
                        entries.append({
                            "key": key_path,
                            "name": _safe_str(value.name),
                            "value": _safe_str(value.value),
                        })
                except Exception:
                    continue
        except Exception as e:
            logger.warning(f"Registry autoruns extraction: {e}")
        return entries

    def _extract_amcache(self, target) -> list[dict]:
        """Extract Amcache entries — application execution tracking."""
        entries = []
        try:
            for entry in target.amcache():
                entries.append({
                    "path": _safe_str(getattr(entry, 'path', '')),
                    "sha1": _safe_str(getattr(entry, 'sha1', '')),
                    "name": _safe_str(getattr(entry, 'name', '')),
                    "publisher": _safe_str(getattr(entry, 'publisher', '')),
                    "version": _safe_str(getattr(entry, 'version', '')),
                    "last_modified": _safe_str(getattr(entry, 'last_modified', '')),
                    "install_date": _safe_str(getattr(entry, 'install_date', '')),
                })
                if len(entries) >= 1000:
                    break
        except Exception as e:
            logger.warning(f"Amcache extraction: {e}")
        return entries

    def _extract_shimcache(self, target) -> list[dict]:
        """Extract Shimcache/AppCompatCache — program execution evidence."""
        entries = []
        try:
            for entry in target.shimcache():
                entries.append({
                    "path": _safe_str(getattr(entry, 'path', '')),
                    "last_modified": _safe_str(getattr(entry, 'last_modified', '')),
                    "index": getattr(entry, 'index', None),
                })
                if len(entries) >= 1000:
                    break
        except Exception as e:
            logger.warning(f"Shimcache extraction: {e}")
        return entries

    def _extract_userassist(self, target) -> list[dict]:
        """Extract UserAssist — GUI program execution tracking."""
        entries = []
        try:
            for entry in target.userassist():
                entries.append({
                    "path": _safe_str(getattr(entry, 'path', '')),
                    "run_count": getattr(entry, 'number_of_executions', 0),
                    "last_executed": _safe_str(getattr(entry, 'last_execution_date_time', '')),
                    "focus_time": getattr(entry, 'application_focus_duration', 0),
                })
                if len(entries) >= 500:
                    break
        except Exception as e:
            logger.warning(f"UserAssist extraction: {e}")
        return entries

    def _extract_recyclebin(self, target) -> list[dict]:
        """Extract Recycle Bin entries."""
        entries = []
        try:
            for entry in target.recyclebin():
                entries.append({
                    "path": _safe_str(getattr(entry, 'path', '')),
                    "deleted_time": _safe_str(getattr(entry, 'deleted_time', '')),
                    "filesize": getattr(entry, 'filesize', 0),
                })
                if len(entries) >= 500:
                    break
        except Exception as e:
            logger.warning(f"Recycle Bin extraction: {e}")
        return entries

    def _extract_shellbags(self, target) -> list[dict]:
        """Extract Shellbags — user directory navigation history."""
        entries = []
        try:
            for entry in target.shellbags():
                entries.append({
                    "path": _safe_str(getattr(entry, 'path', '')),
                    "last_accessed": _safe_str(getattr(entry, 'last_access', '')),
                    "last_modified": _safe_str(getattr(entry, 'last_write', '')),
                    "creation": _safe_str(getattr(entry, 'creation_date', '')),
                })
                if len(entries) >= 500:
                    break
        except Exception as e:
            logger.warning(f"Shellbags extraction: {e}")
        return entries
