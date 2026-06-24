"""
detection/processes.py — process, service, and scheduled task detection.

Covers:
  - _detect_processes: parent-child anomalies, suspicious command lines,
    suspicious paths, system-process masquerading, LOLBin tracking
  - _detect_services: service binary location/command checks, unquoted
    service paths
  - _detect_tasks: scheduled task command/path checks

Grouped together because they're all "things that run" — the same
SUSPICIOUS_CMDLINE / SUSPICIOUS_PATHS signature sets apply to all three,
just applied to different artifact shapes (process list vs. service list
vs. task list).
"""

from __future__ import annotations
import re

from app.detection.base import SUSPICIOUS_CMDLINE, LOLBINS

# System processes that should only ever run from a specific path — anything
# else is masquerading (e.g. a malware sample named svchost.exe in Temp).
SYSTEM_PROCESSES = {
    "svchost.exe": r"\\Windows\\System32\\svchost\.exe",
    "lsass.exe": r"\\Windows\\System32\\lsass\.exe",
    "services.exe": r"\\Windows\\System32\\services\.exe",
    "csrss.exe": r"\\Windows\\System32\\csrss\.exe",
    "winlogon.exe": r"\\Windows\\System32\\winlogon\.exe",
    "explorer.exe": r"\\Windows\\explorer\.exe",
    "smss.exe": r"\\Windows\\System32\\smss\.exe",
    "wininit.exe": r"\\Windows\\System32\\wininit\.exe",
    "spoolsv.exe": r"\\Windows\\System32\\spoolsv\.exe",
    "taskhostw.exe": r"\\Windows\\System32\\taskhostw\.exe",
}

KNOWN_GOOD_SERVICE_PATHS = (
    "\\windows\\system32\\", "\\windows\\syswow64\\",
    "\\windows\\microsoft.net\\", "\\windows\\servicing\\",
    "\\program files\\windows defender\\",
    "\\program files\\microsoft\\", "\\program files (x86)\\microsoft\\",
    "\\program files\\common files\\microsoft shared\\",
)
KNOWN_GOOD_SERVICE_NAMES = {
    "msiserver", "trustedinstaller", "wuauserv", "bits", "wsearch",
    "windefend", "wscsvc", "securityhealthservice", "sense",
    "diagtrack", "dps", "wdiservicehost",
}


def _is_known_good_service(name, path_l: str) -> bool:
    """Heuristic allowlist for benign Windows/vendor services."""
    if name and str(name).lower() in KNOWN_GOOD_SERVICE_NAMES:
        return True
    if any(g in path_l for g in KNOWN_GOOD_SERVICE_PATHS):
        # ...unless the command line carries an obviously malicious payload
        if not re.search(r"-enc\b|frombase64|downloadstring|iex\s*\(", path_l):
            return True
    return False


# ── Process detection ──

def detect_processes(engine, key: str, rows: list[dict]) -> None:
    # Build PID → name map for parent-child analysis
    pid_map = {}
    for proc in rows:
        pid = engine._get(proc, ["Pid", "pid", "ProcessId", "PID"])
        name = engine._get(proc, ["Name", "name", "ProcessName"]).lower()
        if pid:
            pid_map[str(pid)] = name

    # Suspicious parent-child relationships
    suspicious_parents = {
        "winword.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        "excel.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"],
        "outlook.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"],
        "powerpnt.exe": ["powershell.exe", "cmd.exe", "wscript.exe"],
        "w3wp.exe": ["cmd.exe", "powershell.exe", "net.exe", "whoami.exe"],
        "sqlservr.exe": ["cmd.exe", "powershell.exe"],
        "services.exe": ["cmd.exe", "powershell.exe"],  # unusual
    }

    for idx, proc in enumerate(rows):
        name = engine._get(proc, ["Name", "name", "ProcessName", "Exe"]).lower()
        path = engine._get(proc, ["Exe", "Path", "path", "CommandLine", "ExecutablePath"])
        cmdline = engine._get(proc, ["CommandLine", "cmdline", "Cmd"])
        pid = engine._get(proc, ["Pid", "pid", "ProcessId", "PID"])
        ppid = engine._get(proc, ["Ppid", "ppid", "ParentProcessId", "PPID"])

        evidence_base = {
            "row_index": idx, "pid": pid, "ppid": ppid,
            "name": name, "path": path, "cmdline": cmdline[:300],
        }

        # Parent-child anomaly
        parent_name = pid_map.get(str(ppid), "")
        if parent_name in suspicious_parents:
            child_base = name.split("\\")[-1]
            if child_base in suspicious_parents[parent_name]:
                engine._add_finding(
                    "process_anomaly", "high",
                    f"Suspicious parent-child: {parent_name} → {child_base}",
                    f"Office/server process '{parent_name}' (PID {ppid}) spawned "
                    f"'{child_base}' (PID {pid}) — common macro/exploit execution pattern",
                    key, evidence_base,
                    score=80, mitre="T1566.001",  # Spearphishing Attachment
                )

        # Check command-line patterns
        full_text = f"{path} {cmdline}"
        for pattern, desc, sev in SUSPICIOUS_CMDLINE:
            if re.search(pattern, full_text, re.IGNORECASE):
                engine._add_finding(
                    "process_anomaly", sev,
                    f"Suspicious process command: {desc}",
                    f"Process '{name}' (PID {pid}) exhibits {desc}. Command: {cmdline[:200]}",
                    key, evidence_base,
                    score=80 if sev in ("critical", "high") else 50,
                    mitre="T1059",
                )

        # Check suspicious paths
        for pattern, desc, sev in engine._check_suspicious_paths(path, proc_name=name):
            engine._add_finding(
                "process_anomaly", sev,
                f"Process from suspicious location: {desc}",
                f"Process '{name}' (PID {pid}) running from: {path}",
                key, evidence_base,
                score=60, mitre="T1036",
            )

        # Process masquerading — system process from wrong path
        if name in SYSTEM_PROCESSES and path:
            expected = SYSTEM_PROCESSES[name]
            if not re.search(expected, path, re.IGNORECASE):
                engine._add_finding(
                    "process_anomaly", "critical",
                    f"Process masquerading: {name} from wrong path",
                    f"System process '{name}' should run from System32 but runs from: {path}",
                    key, evidence_base,
                    score=95, mitre="T1036.005",
                )

        # LOLBin usage tracking
        if name in LOLBINS and cmdline:
            engine.evidence_index["lolbins"].append(evidence_base)


# ── Service detection ──

def detect_services(engine, key: str, rows: list[dict]) -> None:
    for idx, svc in enumerate(rows):
        name = engine._get(svc, ["Name", "name", "ServiceName", "DisplayName"])
        path = engine._get(svc, ["PathName", "ImagePath", "image_path", "Exe", "path", "CommandLine"])
        account = engine._get(svc, ["StartName", "account", "ServiceAccount"])
        start = engine._get(svc, ["StartMode", "start_type", "StartType"])

        if not path:
            continue
        path_l = str(path).lower()

        evidence = {
            "row_index": idx, "name": name, "path": path,
            "account": account, "start_mode": start,
        }

        # Skip well-known legitimate Windows/system service binaries to
        # cut false positives (msiexec, svchost, .NET, Defender, etc.).
        if _is_known_good_service(name, path_l):
            continue

        # Service binary in suspicious location — respect the PATTERN's
        # own severity instead of forcing "high". ProgramData alone is
        # 'low' (lots of legit software lives there), not high.
        bin_name = str(path).split("\\")[-1].split(" ")[0]
        for pattern, desc, sev in engine._check_suspicious_paths(path, proc_name=bin_name):
            # Only flag medium+ path findings for services; 'low'
            # locations like ProgramData are too noisy on their own.
            if sev in ("critical", "high", "medium"):
                engine._add_finding(
                    "persistence", sev,
                    "Service binary in suspicious location",
                    f"Service '{name}' runs binary from: {path} ({desc})",
                    key, evidence,
                    score={"critical": 90, "high": 75, "medium": 50}.get(sev, 50),
                    mitre="T1543.003",
                )
            break

        # Service with encoded/suspicious command — but require the match
        # to be substantive (avoid matching benign flags like msiexec /V).
        for pattern, desc, sev in SUSPICIOUS_CMDLINE:
            m = re.search(pattern, path, re.IGNORECASE)
            if m and len(m.group(0)) >= 4:  # ignore trivial 2-3 char matches
                engine._add_finding(
                    "persistence", sev if sev in ("critical", "high") else "medium",
                    f"Service with suspicious command: {desc}",
                    f"Service '{name}' command contains {desc}: {path[:200]}",
                    key, evidence,
                    score=70, mitre="T1543.003",
                )
                break

        # Unquoted service path (privilege escalation)
        if path and not path.startswith('"') and " " in path and ".exe" in path.lower():
            exe_part = path.lower().split(".exe")[0]
            if " " in exe_part:
                engine._add_finding(
                    "persistence", "medium",
                    "Unquoted service path",
                    f"Service '{name}' has unquoted path with spaces: {path} — privilege escalation risk",
                    key, evidence,
                    score=40, mitre="T1574.009",
                )


# ── Scheduled task detection ──

def detect_tasks(engine, key: str, rows: list[dict]) -> None:
    for idx, task in enumerate(rows):
        name = engine._get(task, ["Name", "name", "TaskName"])
        command = engine._get(task, ["Command", "command", "Action", "Exe", "Arguments"])
        args = engine._get(task, ["Arguments", "args", "Args"])

        full = f"{command} {args}"
        evidence = {
            "row_index": idx, "name": name, "command": command, "args": args[:200],
        }

        for pattern, desc, sev in SUSPICIOUS_CMDLINE:
            if re.search(pattern, full, re.IGNORECASE):
                engine._add_finding(
                    "persistence", sev,
                    f"Scheduled task with suspicious command: {desc}",
                    f"Task '{name}' exhibits {desc}: {full[:200]}",
                    key, evidence,
                    score=80, mitre="T1053.005",  # Scheduled Task
                )

        task_bin_name = str(command).split("\\")[-1].split(" ")[0]
        for pattern, desc, sev in engine._check_suspicious_paths(full, proc_name=task_bin_name):
            engine._add_finding(
                "persistence", "medium",
                f"Scheduled task references suspicious path",
                f"Task '{name}' references {desc}: {full[:200]}",
                key, evidence,
                score=50, mitre="T1053.005",
            )
