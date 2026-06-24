"""
Collector Manager — handles upload processing for:
  1. Our standalone collector scripts (ir_collect.ps1 / ir_collect.sh)
  2. Velociraptor offline collector ZIP files
  3. Generic JSON/CSV/tar.gz uploads

Velociraptor collector ZIP structure:
  Collection-HOSTNAME-TIMESTAMP/
  ├── results/
  │   ├── Windows.System.Pslist.json
  │   ├── Windows.Network.Netstat.json
  │   └── ...
  ├── uploads/
  │   └── auto/ or file/ or ntfs/
  │       └── C%3A/Windows/System32/config/SAM
  ├── collection_context.json
  └── log.json

These ZIPs are often password-protected (default: "infected").
"""

import json
import logging
import asyncio
import re
import zipfile
import tarfile
import tempfile
import io
from pathlib import Path, PurePosixPath
from urllib.parse import unquote

from app.config import get_settings

logger = logging.getLogger(__name__)

VELO_PASSWORDS = [b"infected", b"password", b"velociraptor", b""]

# IR-relevant Event IDs to extract
IR_EVENT_IDS = {
    4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 4756,
    7045, 7040, 1102,  # Security
    4103, 4104,  # PowerShell
    1, 3, 5, 7, 8, 11, 12, 13, 15, 22, 23, 25,  # Sysmon
    106, 140, 141, 200, 201,  # Task Scheduler
}


def _parse_evtx_bytes(data: bytes, max_records: int = 0) -> list[dict]:
    """Parse EVTX binary data using dissect.eventlog.

    IR REQUIREMENT: every event is parsed — no sampling, no caps. Forensic
    analysis cannot skip rows. max_records=0 means unlimited (default).
    A non-zero max_records is only used as a last-resort safety valve.

    dissect.eventlog.evtx.Evtx is directly iterable, yielding record objects.
    """
    records = []
    try:
        from dissect.eventlog import evtx
        fh = io.BytesIO(data)
        parser = evtx.Evtx(fh)

        for record in parser:
            try:
                rec = _evtx_record_to_dict(record)
                if rec and rec.get("event_id") is not None:
                    records.append(rec)
            except Exception:
                continue
            # Safety valve only if explicitly set (0 = unlimited)
            if max_records and len(records) >= max_records:
                logger.warning(f"EVTX hit safety cap of {max_records} events")
                break

    except ImportError:
        records.append({"error": "dissect.eventlog not installed"})
    except Exception as e:
        logger.warning(f"EVTX parse error: {e}")
    return records


def _evtx_record_to_dict(record) -> dict:
    """Convert a dissect.eventlog record into a normalized dict.

    dissect.eventlog KeyValueCollection objects expose ALL event fields via
    .items() as a flat dict — Image, CommandLine, ParentImage, GrantedAccess,
    PipeName, TargetFilename, etc. We capture ALL of them so that
    sigma_engine.py and detection/sysmon.py can match on them directly.

    Previously this function only saved 5 fields (event_id, timestamp,
    provider, channel, computer) and discarded everything else into a 'data'
    string — causing Sigma rules and the sysmon detector to see empty fields
    and miss ~145 of 278 EVTX attack samples (all Sysmon-based files).
    """
    out = {}

    # dissect KeyValueCollection supports .items() — gives every field flat,
    # without needing to enumerate known keys in advance.
    try:
        raw = dict(record.items())
    except Exception:
        # Fallback for older dissect versions or other record shapes
        if hasattr(record, "_asdict"):
            try:
                raw = record._asdict()
            except Exception:
                raw = {}
        else:
            raw = {}

    # Copy ALL raw fields into out so Sigma rules and sysmon.py can access
    # Image, CommandLine, ParentImage, TargetFilename, GrantedAccess, etc.
    for k, v in raw.items():
        if v is not None:
            out[k] = v

    # Normalize EventID — raw value is an int from dissect; also expose as
    # string under 'EventID' since some Sigma rules compare it as a string.
    eid = raw.get("EventID") or raw.get("event_id") or raw.get("Event_EventID")
    try:
        eid = int(eid) if eid is not None else None
    except (ValueError, TypeError):
        if isinstance(eid, dict):
            try:
                eid = int(eid.get("#text") or eid.get("text") or 0)
            except (ValueError, TypeError):
                eid = None
        else:
            eid = None

    out["event_id"] = eid
    # Sigma rules that use EventID as string condition need this alias
    out["EventID"] = str(eid) if eid is not None else ""
    # Normalized fields for cross-source compatibility
    out["timestamp"] = str(raw.get("TimeCreated_SystemTime") or raw.get("TimeCreated") or raw.get("timestamp") or "")
    out["provider"] = str(raw.get("Provider_Name") or raw.get("Provider") or raw.get("ProviderName") or "")
    out["channel"] = str(raw.get("Channel") or raw.get("channel") or raw.get("LogName") or "")
    out["computer"] = str(raw.get("Computer") or raw.get("computer") or raw.get("Hostname") or "")
    # Full record as fallback text search target
    out["data"] = str(raw)[:800]

    return out


def _parse_registry_bytes(data: bytes, hive_name: str,
                           max_values: int = 500) -> list[dict]:
    """Parse registry hive binary data using dissect.regf."""
    entries = []
    try:
        from dissect.regf import regf
        fh = io.BytesIO(data)
        hive = regf.RegistryHive(fh)

        # Keys of interest per hive type
        interesting_keys = {
            "SAM": [
                "SAM\\Domains\\Account\\Users",
            ],
            "SYSTEM": [
                "ControlSet001\\Services",
                "ControlSet001\\Control\\Session Manager\\AppCompatCache",
                "ControlSet001\\Control\\ComputerName\\ComputerName",
            ],
            "SOFTWARE": [
                "Microsoft\\Windows\\CurrentVersion\\Run",
                "Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                "Microsoft\\Windows NT\\CurrentVersion",
            ],
            "SECURITY": [],
        }

        keys_to_check = interesting_keys.get(hive_name.upper(), [])

        for key_path in keys_to_check:
            try:
                key = hive.open(key_path)
                # Get values
                for value in key.values():
                    try:
                        entries.append({
                            "hive": hive_name,
                            "key": key_path,
                            "name": str(value.name),
                            "value": str(value.value)[:200],
                            "type": str(value.type),
                        })
                    except Exception:
                        continue
                # Get subkeys (for services, users)
                for subkey in key.subkeys():
                    try:
                        entry = {
                            "hive": hive_name,
                            "key": f"{key_path}\\{subkey.name}",
                            "name": str(subkey.name),
                        }
                        for v in subkey.values():
                            try:
                                entry[str(v.name)] = str(v.value)[:200]
                            except Exception:
                                continue
                        entries.append(entry)
                    except Exception:
                        continue

                    if len(entries) >= max_values:
                        break
            except Exception:
                continue

        if not keys_to_check:
            # Dump root keys if no specific path
            try:
                for subkey in hive.open("").subkeys():
                    entries.append({
                        "hive": hive_name,
                        "key": str(subkey.name),
                        "name": str(subkey.name),
                        "subkeys": len(list(subkey.subkeys())),
                    })
            except Exception:
                pass

    except ImportError:
        entries.append({"error": "dissect.regf not installed"})
    except Exception as e:
        logger.warning(f"Registry parse error ({hive_name}): {e}")
        entries.append({"error": str(e)})
    return entries
def _parse_csv_to_rows(file_path: Path) -> dict:
    """Parse CSV/TSV into structured rows for the detection engine."""
    import csv as csv_mod
    rows = []
    try:
        text = file_path.read_text(errors="replace")
        dialect = csv_mod.Sniffer().sniff(text[:4096], delimiters=",\t;|")
        reader = csv_mod.DictReader(text.splitlines(), dialect=dialect)
        for i, row in enumerate(reader):
            if i > 200_000:
                break
            rows.append(dict(row))
    except Exception:
        # Fallback: treat as text lines
        rows = [{"raw": line, "timestamp": ""} 
                for line in file_path.read_text(errors="replace").splitlines()
                if line.strip()]
    # Use "siem_export" as key so detection routing picks textlogs detector
    return {"siem_export": rows}


def _parse_textlog_to_rows(file_path: Path) -> dict:
    """Parse text log file into rows with raw line + best-effort timestamp."""
    import re
    TS_RE = re.compile(
        r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'  # ISO
        r'|(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'      # syslog
    )
    rows = []
    for line in file_path.read_text(errors="replace").splitlines():
        if not line.strip():
            continue
        ts_match = TS_RE.search(line)
        rows.append({
            "raw": line,
            "timestamp": ts_match.group(0) if ts_match else "",
        })
        if len(rows) > 500_000:
            break

    # Detect log type from filename for routing key
    name = file_path.name.lower()
    if "auth" in name or "secure" in name:
        key = "authlog"
    elif "apache" in name or "nginx" in name or "access" in name:
        key = "apache"
    elif "suricata" in name or "eve" in name:
        key = "suricata"
    elif "zeek" in name or "bro" in name:
        key = "zeek_conn"
    elif "syslog" in name:
        key = "syslog"
    else:
        key = "textlog"

    return {key: rows}


def _parse_jsonl_to_rows(file_path: Path) -> dict:
    """Parse JSONL (one JSON object per line) — common for Suricata EVE."""
    import json
    rows = []
    for line in file_path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            rows.append(obj if isinstance(obj, dict) else {"raw": line})
        except json.JSONDecodeError:
            rows.append({"raw": line})
        if len(rows) > 200_000:
            break
    return {"suricata": rows}

def _parse_mplog_lines(lines: list[str], source_file: str = "") -> list[dict]:
    """
    Parse Windows Defender MPLog (Microsoft Protection Log) plain-text lines
    into structured events.

    MPLog is collected as raw text by the PowerShell collector (see
    defender_mplogs in ir_collect.ps1) since it's not a binary format like
    EVTX/registry — parsing happens here so the logic lives in one place.

    Covers the 4 documented event types (per Microsoft/CrowdStrike DFIR
    research), each carrying evidence EVTX alone doesn't have:
      - DETECTION_ADD: a threat was found, with the file path or PID involved
      - EMS detection: memory-scan detections — process injection evidence
      - SDN events: file existence + SHA1/SHA256, independent of EVTX
      - Estimated Impact: per-process file-access evidence, including files
        accessed that the process itself may have since deleted

    Returns a list of dicts, one per matched event, with a `event_type`
    field so the detection engine can route by category.
    """
    events = []

    # DETECTION_ADD — e.g.:
    #   2021-07-22T15:38:04.557Z DETECTION_ADD Ransom:Win32/Conti.ZA file:C:\ProgramData\badfile.exe
    #   2021-07-22T15:38:04.557Z DETECTION_ADD Ransom:Win32/Conti.ZA process:pid:100128,ProcessStart:...
    detection_re = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+DETECTION_ADD\s+(?P<threat>\S+)\s+"
        r"(?:file:(?P<file>[^\s,]+)|process:pid:(?P<pid>\d+))"
    )

    # EMS detection — e.g.:
    #   Engine:EMS detection: HackTool:Win64/CobaltStrike.A!!CobaltStrike.A64, sigseq=..., pid=6108
    ems_re = re.compile(
        r"EMS detection:\s*(?P<threat>[^,]+),\s*sigseq=\S+,\s*pid=(?P<pid>\d+)"
    )

    # SDN event — file path followed by sha1/sha2 on nearby lines is too
    # unreliable to regex generically across MPLog format versions; capture
    # the common single-line variant: path + both hashes on one line.
    sdn_re = re.compile(
        r"(?P<file>[A-Za-z]:\\[^\s,]+)\s+.*?[Ss]ha1[:\s]+(?P<sha1>[0-9a-fA-F]{40}).*?"
        r"[Ss]ha2[56]*[:\s]+(?P<sha256>[0-9a-fA-F]{64})"
    )

    # Estimated Impact — e.g.:
    #   2020-06-14T20:11:42.880Z ProcessImageName: explorer.exe, TotalTime: 30,
    #   Count: 11, MaxTime: 15, MaxTimeFile: \Device\...\PuTTY (64-bit).lnk->, EstimatedImpact: 9%
    impact_re = re.compile(
        r"(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+Z)\s+ProcessImageName:\s*(?P<proc>[^,]+),\s*"
        r"TotalTime:\s*(?P<total_time>\d+),\s*Count:\s*(?P<count>\d+).*?"
        r"MaxTimeFile:\s*(?P<max_time_file>[^,]+?)(?:->)?,\s*EstimatedImpact:\s*(?P<impact>[\d.]+)%"
    )

    for line in lines:
        if not line or not line.strip():
            continue

        m = detection_re.search(line)
        if m:
            events.append({
                "event_type": "detection",
                "timestamp": m.group("ts"),
                "threat_name": m.group("threat"),
                "file": m.group("file") or "",
                "pid": m.group("pid") or "",
                "source_file": source_file,
                "raw": line[:300],
            })
            continue

        m = ems_re.search(line)
        if m:
            events.append({
                "event_type": "ems_detection",
                "threat_name": m.group("threat").strip(),
                "pid": m.group("pid"),
                "source_file": source_file,
                "raw": line[:300],
            })
            continue

        m = sdn_re.search(line)
        if m:
            events.append({
                "event_type": "sdn",
                "file": m.group("file"),
                "sha1": m.group("sha1"),
                "sha256": m.group("sha256"),
                "source_file": source_file,
                "raw": line[:300],
            })
            continue

        m = impact_re.search(line)
        if m:
            events.append({
                "event_type": "estimated_impact",
                "timestamp": m.group("ts"),
                "process": m.group("proc").strip(),
                "files_accessed": m.group("count"),
                "max_time_file": m.group("max_time_file").strip(),
                "estimated_impact_pct": m.group("impact"),
                "source_file": source_file,
                "raw": line[:300],
            })
            continue

    return events


class CollectorManager:
    def __init__(self):
        self.settings = get_settings()

    async def process_upload(self, file_path: str, incident_title: str = "") -> dict:
        """Process an uploaded collector result. Auto-detects format.

        The heavy parsing (ZIP extraction, EVTX/registry binary parsing) is
        CPU-bound and synchronous, so we run it in a worker thread. This keeps
        the async event loop free to serve the SSE progress stream — otherwise
        a long parse would block heartbeats and the client would lose the
        connection ("Connection to stream lost").
        """
        file_path = Path(file_path)
        if not file_path.exists():
            return {"error": "File not found", "data": {"error": "File not found"}}

        result = await asyncio.to_thread(
            self._process_upload_sync, file_path, incident_title
        )
        return result

    def _process_upload_sync(self, file_path: Path, incident_title: str = "") -> dict:
        """Synchronous parsing core, run inside a thread by process_upload."""
        extracted_data = {}
        source_type = "unknown"

        if file_path.suffix.lower() == ".zip":
            extracted_data, source_type = self._extract_zip_smart(file_path)
        elif file_path.name.endswith(".tar.gz") or file_path.suffix == ".gz":
            extracted_data = self._extract_targz(file_path)
            source_type = "tar.gz"
        elif file_path.suffix.lower() in (".json", ".jsonl"):
            extracted_data = self._read_json(file_path)
            source_type = "json"
        elif file_path.suffix.lower() in (".csv", ".tsv"):
            extracted_data = _parse_csv_to_rows(file_path)
            source_type = "csv"
        elif file_path.suffix.lower() in (".log", ".txt", ".syslog", ".out"):
            extracted_data = _parse_textlog_to_rows(file_path)
            source_type = "textlog"
        elif file_path.suffix.lower() in (".jsonl",):
            extracted_data = _parse_jsonl_to_rows(file_path)
            source_type = "textlog"
        else:
            extracted_data = _parse_textlog_to_rows(file_path)
            source_type = "textlog"

        self._postprocess_defender_mplogs(extracted_data)

        total_items = sum(
            len(v) if isinstance(v, list) else 1
            for k, v in extracted_data.items()
            if k not in ("_metadata", "error")
        )

        return {
            "filename": file_path.name,
            "size_bytes": file_path.stat().st_size,
            "source_type": source_type,
            "data_types": [k for k in extracted_data.keys() if k != "_metadata"],
            "total_items": total_items,
            "data": extracted_data,
        }

    def _postprocess_defender_mplogs(self, extracted_data: dict) -> None:
        """
        Transform the raw defender_mplogs collector output (one entry per
        MPLog file, each with a `lines` array of raw text) into parsed,
        structured events under the same key, ready for the detection
        engine. Runs after any extraction path (zip/json/targz), since the
        collector output shape is the same regardless of container format.

        Mutates extracted_data in place. No-op if the key isn't present.
        """
        raw = extracted_data.get("defender_mplogs")
        if not raw or not isinstance(raw, list):
            return

        all_events = []
        for file_entry in raw:
            if not isinstance(file_entry, dict):
                continue
            if file_entry.get("error"):
                logger.warning(f"MPLog file unreadable: {file_entry.get('error')}")
                continue
            lines = file_entry.get("lines", [])
            filename = file_entry.get("filename", "unknown")
            if not lines:
                continue
            events = _parse_mplog_lines(lines, source_file=filename)
            all_events.extend(events)

        if all_events:
            logger.info(
                f"MPLog: parsed {len(all_events)} events "
                f"({sum(1 for e in all_events if e['event_type'] == 'detection')} detections, "
                f"{sum(1 for e in all_events if e['event_type'] == 'ems_detection')} EMS detections, "
                f"{sum(1 for e in all_events if e['event_type'] == 'sdn')} SDN, "
                f"{sum(1 for e in all_events if e['event_type'] == 'estimated_impact')} impact) "
                f"from {len(raw)} MPLog file(s)"
            )
        extracted_data["defender_mplogs"] = all_events

    def _extract_zip_smart(self, zip_path: Path) -> tuple[dict, str]:
        """
        Smart ZIP extraction — detects Velociraptor vs standalone collector.
        Tries passwords for encrypted ZIPs.
        """
        zf = None
        password_used = None

        # Try to open, with password attempts for encrypted ZIPs
        try:
            zf = zipfile.ZipFile(zip_path, 'r')
            # Check if encrypted by trying to read first file
            names = zf.namelist()
            if names:
                try:
                    zf.read(names[0])
                    password_used = None
                except RuntimeError:
                    # Encrypted — try passwords
                    zf.close()
                    zf = None
                    for pwd in VELO_PASSWORDS:
                        try:
                            zf = zipfile.ZipFile(zip_path, 'r')
                            zf.setpassword(pwd)
                            zf.read(names[0])
                            password_used = pwd.decode() if pwd else None
                            logger.info(f"ZIP decrypted with password: {password_used or '(empty)'}")
                            break
                        except (RuntimeError, zipfile.BadZipFile):
                            if zf:
                                zf.close()
                            zf = None
                            continue

        except zipfile.BadZipFile:
            return {"error": "Invalid ZIP file"}, "error"
        except Exception as e:
            return {"error": str(e)}, "error"

        if zf is None:
            return {
                "error": "Encrypted ZIP — could not decrypt. "
                         "Try passwords: infected, password, velociraptor"
            }, "error"

        try:
            names = zf.namelist()

            # Detect source type
            is_velociraptor = self._is_velociraptor_zip(names)

            if is_velociraptor:
                logger.info("Detected Velociraptor collector ZIP")
                data = self._parse_velociraptor_zip(zf, names, password_used)
                return data, "velociraptor"
            else:
                logger.info("Detected standard collector ZIP")
                data = self._parse_standard_zip(zf, names)
                return data, "collector"

        finally:
            zf.close()

    def _is_velociraptor_zip(self, names: list[str]) -> bool:
        """Detect if this ZIP is from a Velociraptor offline collector."""
        for name in names:
            decoded = unquote(name).lower()
            if "collection_context" in decoded:
                return True
            if "/results/" in decoded or "results/" in decoded:
                if any(art in decoded for art in [
                    "windows.", "linux.", "generic.", "server.",
                    "artifact.", "custom.", "triage",
                ]):
                    return True
            if "uploads/" in decoded:
                return True
        return False

    def _parse_velociraptor_zip(self, zf: zipfile.ZipFile,
                                 names: list[str],
                                 password: str | None) -> dict:
        """
        Parse a Velociraptor offline collector ZIP.
        Extracts results JSON files and collection metadata.
        """
        data = {}
        metadata = {
            "source": "velociraptor_collector",
            "password": password,
        }

        # Parse collection_context.json for metadata
        for name in names:
            decoded = unquote(name)
            if decoded.endswith("collection_context.json"):
                try:
                    content = zf.read(name).decode('utf-8', errors='replace')
                    ctx = json.loads(content)
                    metadata["hostname"] = ctx.get("client_id", "")
                    metadata["create_time"] = ctx.get("create_time", "")
                    metadata["artifacts_collected"] = ctx.get("artifacts_with_results", [])
                    metadata["total_collected_rows"] = ctx.get("total_collected_rows", 0)
                    metadata["total_uploaded_bytes"] = ctx.get("total_uploaded_bytes", 0)
                    metadata["state"] = ctx.get("state", "")
                except Exception as e:
                    logger.warning(f"Could not parse collection_context: {e}")
                break

        # Parse results files (URL-decode paths first)
        result_files = []
        upload_files = []
        for name in names:
            decoded = unquote(name).replace("\\", "/")
            lower = decoded.lower()
            if "results/" in lower and (decoded.endswith(".json") or decoded.endswith(".jsonl")):
                if not decoded.endswith(".index"):
                    result_files.append(name)
            if "uploads/" in lower and not decoded.endswith("/"):
                upload_files.append(name)

        # Also collect EVTX / registry-hive files found ANYWHERE in the ZIP,
        # not only under an "uploads/" folder. Plain folder ZIPs (e.g. the
        # EVTX-ATTACK-SAMPLES dataset, which groups logs as
        # "Defense Evasion/foo.evtx") have no Velociraptor "uploads/" prefix,
        # so without this their .evtx files were silently never parsed.
        for name in names:
            if name.endswith("/"):
                continue
            decoded = unquote(name).replace("\\", "/")
            lower = decoded.lower()
            basename = PurePosixPath(decoded).name.upper()
            is_binary_artifact = (
                lower.endswith(".evtx")
                or basename in ("SAM", "SYSTEM", "SOFTWARE", "SECURITY",
                                "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT")
            )
            if is_binary_artifact and name not in upload_files:
                upload_files.append(name)

        logger.info(f"Found {len(result_files)} result files, {len(upload_files)} uploaded files")

        for name in result_files:
            try:
                content = zf.read(name).decode('utf-8', errors='replace')
                if not content.strip():
                    continue

                # Extract artifact name from decoded path
                decoded = unquote(name).replace("\\", "/")
                path_parts = PurePosixPath(decoded)
                artifact_name = path_parts.stem
                artifact_name = artifact_name.replace(".", "_").replace("%2F", "_")

                # Parse JSONL (one JSON object per line — Velociraptor default)
                rows = []
                for line in content.strip().split('\n'):
                    line = line.strip()
                    if line:
                        try:
                            row = json.loads(line)
                            if isinstance(row, dict):
                                # Track the source file path inside the ZIP
                                row.setdefault("_source_file", decoded)
                                rows.append(row)
                            elif isinstance(row, list):
                                for r in row:
                                    if isinstance(r, dict):
                                        r.setdefault("_source_file", decoded)
                                rows.extend(row)
                        except json.JSONDecodeError:
                            continue

                if rows:
                    data[artifact_name] = rows
                    logger.info(f"  Parsed result: {artifact_name}: {len(rows)} rows")

            except Exception as e:
                logger.warning(f"Could not parse result file {name}: {e}")

        # Parse log.json for any errors
        for name in names:
            if name.endswith("log.json") and "/results/" not in name:
                try:
                    content = zf.read(name).decode('utf-8', errors='replace')
                    logs = []
                    for line in content.strip().split('\n'):
                        if line.strip():
                            try:
                                logs.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    # Only include errors/warnings
                    errors = [
                        l for l in logs
                        if l.get("level", "").lower() in ("error", "warning")
                    ]
                    if errors:
                        metadata["collection_errors"] = errors[:20]
                except Exception:
                    pass
                break

        # ── YARA content scanning of uploaded files ──
        # Every serious DFIR tool scans file CONTENT against malware
        # patterns, not just metadata. We scan executables/scripts straight
        # from the ZIP bytes (no disk extraction needed). Each hit becomes a
        # row in the 'yara_matches' artifact, which the detection engine's
        # yara route turns into findings. 100% offline.
        try:
            from app.yara_scanner import YaraScanner
            scanner = YaraScanner()
            if scanner.available:
                yara_matches = []
                files_scanned = 0
                for uf in upload_files:
                    decoded = unquote(uf).replace("\\", "/")
                    try:
                        info = zf.getinfo(uf)
                    except KeyError:
                        continue
                    if not scanner.should_scan(decoded, info.file_size):
                        continue
                    try:
                        file_bytes = zf.read(uf)
                    except Exception:
                        continue
                    files_scanned += 1
                    for hit in scanner.scan_bytes(file_bytes, filename=decoded):
                        hit["_source_file"] = decoded
                        yara_matches.append(hit)

                if yara_matches:
                    data["yara_matches"] = yara_matches
                    logger.info(
                        f"YARA: {len(yara_matches)} match(es) across {files_scanned} "
                        f"scanned file(s)"
                    )
                else:
                    logger.info(f"YARA: no matches ({files_scanned} file(s) scanned)")
        except Exception as e:
            logger.warning(f"YARA scanning skipped: {e}")

        # upload_files was already correctly identified above (decoded paths).
        # Of those, only EVTX and registry hives are parseable — filter first
        # so we don't iterate hundreds of thousands of irrelevant collected files.
        binary_candidates = []
        for uf in upload_files:
            decoded = unquote(uf).replace("\\", "/")
            lower = decoded.lower()
            basename = PurePosixPath(decoded).name.upper()
            if lower.endswith(".evtx") or basename in (
                "SAM", "SYSTEM", "SOFTWARE", "SECURITY",
                "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT"):
                binary_candidates.append((uf, decoded, lower, basename))

        # Prioritize IR-critical artifacts so they're never cut off by the cap.
        def _priority(c):
            _, decoded, lower, basename = c
            if basename in ("SAM", "SYSTEM", "SOFTWARE", "SECURITY"):
                return 0  # registry hives first
            if any(k in lower for k in ["security.evtx", "system.evtx",
                    "powershell", "sysmon", "terminalservices", "taskscheduler",
                    "windows defender", "wmi-activity", "/application.evtx"]):
                return 1  # key IR event logs
            return 2  # everything else
        binary_candidates.sort(key=_priority)

        logger.info(f"Found {len(upload_files)} uploaded files, "
                    f"{len(binary_candidates)} parseable (EVTX/registry)")

        if binary_candidates:
            metadata["uploaded_files"] = []
            evtx_data = {}
            registry_data = {}

            # Parse EVERY EVTX/registry candidate — no cap. IR cannot skip
            # forensic artifacts. (Sorted so IR-critical ones parse first.)
            for uf, decoded, lower, basename in binary_candidates:
                try:
                    info = zf.getinfo(uf)
                except KeyError:
                    continue
                metadata["uploaded_files"].append({
                    "path": decoded, "size": info.file_size,
                })

                # Parse EVERY EVTX file. IR completeness: a small log can still
                # hold critical events (we've seen 3-8 real events in 69KB logs).
                # The parser returns empty for true template files — cheap — but
                # we never skip a file that might contain evidence.
                if lower.endswith(".evtx") and info.file_size > 0:
                    log_name = PurePosixPath(decoded).stem
                    try:
                        raw = zf.read(uf)
                        records = _parse_evtx_bytes(raw)
                        real = [r for r in records if r.get("event_id") is not None]
                        if real:
                            key = f"evtx_{log_name}"
                            evtx_data[key] = real
                            logger.info(f"  EVTX {log_name} ({info.file_size} bytes) → {len(real)} events")
                    except Exception as e:
                        logger.warning(f"  EVTX parse failed for {uf}: {e}")

                # Parse registry hives (SAM, SYSTEM, SOFTWARE, SECURITY)
                elif info.file_size > 0 and info.file_size < 500_000_000:
                    # Match registry hive files by name at end of path
                    basename = PurePosixPath(decoded).name.upper()
                    if basename in ("SAM", "SYSTEM", "SOFTWARE", "SECURITY",
                                     "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT"):
                        hive_name = basename.replace(".", "_")
                        try:
                            raw = zf.read(uf)
                            hive_name = PurePosixPath(decoded).stem.upper()
                            logger.info(f"  Parsing registry: {hive_name} ({info.file_size} bytes)")
                            entries = _parse_registry_bytes(raw, hive_name)
                            if entries:
                                key = f"registry_{hive_name}"
                                registry_data[key] = entries
                                logger.info(f"    → {len(entries)} entries")
                        except Exception as e:
                            logger.warning(f"  Registry parse failed for {uf}: {e}")

            # Merge parsed binary data into results
            data.update(evtx_data)
            data.update(registry_data)

            if evtx_data or registry_data:
                metadata["binary_files_parsed"] = {
                    "evtx_files": len(evtx_data),
                    "evtx_total_events": sum(len(v) for v in evtx_data.values()),
                    "registry_hives": len(registry_data),
                    "registry_total_entries": sum(len(v) for v in registry_data.values()),
                }
                logger.info(
                    f"Binary parsing: {len(evtx_data)} EVTX files "
                    f"({sum(len(v) for v in evtx_data.values())} events), "
                    f"{len(registry_data)} registry hives "
                    f"({sum(len(v) for v in registry_data.values())} entries)"
                )
            else:
                logger.warning(
                    "No binary files were parsed. Check that uploads contain "
                    ".evtx or registry hive files (SAM/SYSTEM/SOFTWARE/SECURITY)"
                )

        data["_metadata"] = metadata

        if not data or (len(data) == 1 and "_metadata" in data):
            data["warning"] = (
                "No parsed results found in the ZIP. "
                "The collector may have only uploaded raw files (evtx, registry hives). "
                "These require the Disk Image analyzer to parse."
            )

        return data

    def _parse_standard_zip(self, zf: zipfile.ZipFile,
                             names: list[str]) -> dict:
        """Parse a standard collector ZIP (our ir_collect scripts).

        Handles JSON/JSONL/CSV results AND binary forensic artifacts
        (.evtx event logs, registry hives) found ANYWHERE in the archive —
        e.g. plain folder ZIPs like the EVTX-ATTACK-SAMPLES dataset that group
        logs as "Defense Evasion/foo.evtx" with no Velociraptor structure.
        """
        data = {}
        for name in names:
            if name.endswith(('.json', '.jsonl')):
                try:
                    content = zf.read(name).decode('utf-8', errors='replace')
                    key = PurePosixPath(name).stem

                    if name.endswith('.jsonl'):
                        rows = []
                        for line in content.strip().split('\n'):
                            if line.strip():
                                try:
                                    rows.append(json.loads(line))
                                except json.JSONDecodeError:
                                    continue
                        if rows:
                            data[key] = rows
                    else:
                        parsed = json.loads(content)
                        data[key] = parsed
                except Exception as e:
                    logger.warning(f"Could not parse {name}: {e}")

            elif name.endswith('.csv'):
                try:
                    data[PurePosixPath(name).stem] = (
                        zf.read(name).decode('utf-8', errors='replace')[:200000]
                    )
                except Exception:
                    pass

        # Parse EVTX / registry hives found anywhere in the ZIP.
        self._parse_binary_artifacts(zf, names, data)
        return data

    def _parse_binary_artifacts(self, zf: zipfile.ZipFile,
                                 names: list[str], data: dict) -> None:
        """
        Find and parse EVTX event logs and registry hives anywhere in the ZIP,
        merging flat `evtx_<name>` / `registry_<name>` keys into `data`.

        Shared by the standard and Velociraptor parsers so both fully parse
        binary forensic artifacts regardless of folder layout.
        """
        # Collect EVTX + registry-hive candidates by extension/name, anywhere.
        candidates = []
        for name in names:
            if name.endswith("/"):
                continue
            decoded = unquote(name).replace("\\", "/")
            lower = decoded.lower()
            basename = PurePosixPath(decoded).name.upper()
            if lower.endswith(".evtx") or basename in (
                "SAM", "SYSTEM", "SOFTWARE", "SECURITY",
                "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT"):
                candidates.append((name, decoded, lower, basename))

        if not candidates:
            return

        logger.info(f"Found {len(candidates)} binary artifacts (EVTX/registry) to parse")

        evtx_count = 0
        evtx_events = 0
        reg_count = 0
        for name, decoded, lower, basename in candidates:
            try:
                info = zf.getinfo(name)
            except KeyError:
                continue
            if info.file_size == 0:
                continue

            if lower.endswith(".evtx"):
                log_name = PurePosixPath(decoded).stem
                try:
                    raw = zf.read(name)
                    records = _parse_evtx_bytes(raw)
                    real = [r for r in records if r.get("event_id") is not None]
                    if real:
                        # Disambiguate same-named logs from different folders
                        key = f"evtx_{log_name}"
                        if key in data:
                            key = f"evtx_{PurePosixPath(decoded).parent.name}_{log_name}"
                        data[key] = real
                        evtx_count += 1
                        evtx_events += len(real)
                        logger.info(f"  EVTX {log_name} ({info.file_size}B) → {len(real)} events")
                except Exception as e:
                    logger.warning(f"  EVTX parse failed for {name}: {e}")

            elif info.file_size < 500_000_000 and basename in (
                "SAM", "SYSTEM", "SOFTWARE", "SECURITY",
                "DEFAULT", "NTUSER.DAT", "USRCLASS.DAT"):
                hive_name = basename.replace(".", "_")
                try:
                    raw = zf.read(name)
                    entries = _parse_registry_bytes(raw, hive_name)
                    if entries:
                        data[f"registry_{hive_name}"] = entries
                        reg_count += 1
                        logger.info(f"  Registry {hive_name} → {len(entries)} entries")
                except Exception as e:
                    logger.warning(f"  Registry parse failed for {name}: {e}")

        if evtx_count or reg_count:
            logger.info(f"Binary parsing: {evtx_count} EVTX files ({evtx_events} events), "
                        f"{reg_count} registry hives")

    def _extract_targz(self, tar_path: Path) -> dict:
        """Parse tar.gz archives (Linux collector output)."""
        data = {}
        try:
            with tarfile.open(tar_path, 'r:gz') as tf:
                for member in tf.getmembers():
                    if member.isfile() and member.name.endswith(('.json', '.jsonl')):
                        try:
                            f = tf.extractfile(member)
                            if f:
                                content = f.read().decode('utf-8', errors='replace')
                                key = PurePosixPath(member.name).stem
                                if member.name.endswith('.jsonl'):
                                    rows = [
                                        json.loads(l)
                                        for l in content.strip().split('\n')
                                        if l.strip()
                                    ]
                                    if rows:
                                        data[key] = rows
                                else:
                                    data[key] = json.loads(content)
                        except Exception as e:
                            logger.warning(f"Could not parse {member.name}: {e}")
        except Exception as e:
            data["error"] = str(e)
        return data

    def _read_json(self, path: Path) -> dict:
        """Read a JSON or JSONL file."""
        content = path.read_text(errors='replace')
        if path.suffix == '.jsonl':
            rows = [
                json.loads(l)
                for l in content.strip().split('\n')
                if l.strip()
            ]
            return {"results": rows}
        return {"results": json.loads(content)}

    async def process_upload_dir(self, dir_path: str) -> dict:
        """Process an extracted collection directory (e.g., Velociraptor output)."""
        dir_path = Path(dir_path)
        if not dir_path.is_dir():
            return {"error": "Not a directory", "data": {"error": "Not a directory"}}

        data = {}
        total_size = 0

        for json_file in sorted(dir_path.rglob("*.json")) + sorted(dir_path.rglob("*.jsonl")):
            if json_file.stat().st_size > 500_000_000:
                continue
            total_size += json_file.stat().st_size

            try:
                content = json_file.read_text(errors='replace')
                key = json_file.stem.replace(".", "_")
                if key in data:
                    key = f"{key}_{json_file.parent.name}"

                if json_file.suffix == '.jsonl' or '\n{' in content[:1000]:
                    rows = []
                    for line in content.strip().split('\n'):
                        if line.strip():
                            try:
                                rows.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                    if rows:
                        data[key] = rows
                else:
                    parsed = json.loads(content)
                    data[key] = parsed
            except Exception as e:
                logger.warning(f"Could not parse {json_file}: {e}")

        source_type = "folder"
        for candidate in dir_path.rglob("collection_context.json"):
            source_type = "velociraptor"
            try:
                ctx = json.loads(candidate.read_text(errors='replace'))
                data["_metadata"] = {
                    "source": "velociraptor_collector",
                    "hostname": ctx.get("client_id", ""),
                    "artifacts_collected": ctx.get("artifacts_with_results", []),
                }
            except Exception:
                pass
            break

        self._postprocess_defender_mplogs(data)

        return {
            "filename": dir_path.name,
            "size_bytes": total_size,
            "source_type": source_type,
            "data_types": [k for k in data.keys() if k != "_metadata"],
            "total_items": sum(
                len(v) if isinstance(v, list) else 1
                for k, v in data.items() if k != "_metadata"
            ),
            "data": data,
        }

    @staticmethod
    def summarize_for_llm(data: dict, max_chars: int = 15000) -> str:
        """
        Create a compact summary of parsed collection data for LLM analysis.
        Instead of truncating raw JSON, extracts the most important items
        and creates a structured summary that fits in the context window.
        """
        sections = []
        metadata = data.pop("_metadata", {})

        if metadata:
            sections.append(f"=== COLLECTION METADATA ===\n"
                          f"Source: {metadata.get('source', 'unknown')}\n"
                          f"Hostname: {metadata.get('hostname', 'unknown')}\n"
                          f"Artifacts: {metadata.get('artifacts_collected', [])}\n")

        for key, value in data.items():
            if key.startswith("error") or key.startswith("warning"):
                continue

            section = f"\n=== {key.upper()} ===\n"

            if isinstance(value, list):
                section += f"Total items: {len(value)}\n"
                # Take first N items (most recent/important)
                sample = value[:20]
                for item in sample:
                    if isinstance(item, dict):
                        # Create one-line summary per item
                        line_parts = []
                        for k, v in item.items():
                            v_str = str(v)[:100]
                            if v_str and v_str != "" and v_str != "None":
                                line_parts.append(f"{k}={v_str}")
                        if line_parts:
                            section += "  " + " | ".join(line_parts[:6]) + "\n"
                    else:
                        section += f"  {str(item)[:200]}\n"

                if len(value) > 20:
                    section += f"  ... and {len(value) - 20} more items\n"

            elif isinstance(value, dict):
                section += json.dumps(value, indent=2, default=str)[:2000] + "\n"
            elif isinstance(value, str):
                section += value[:2000] + "\n"

            sections.append(section)

            # Check total size
            total = sum(len(s) for s in sections)
            if total > max_chars:
                sections.append(f"\n=== TRUNCATED (total data exceeds {max_chars} chars) ===\n")
                break

        return "\n".join(sections)
