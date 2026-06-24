"""
detection/sysmon.py — Sysmon (Microsoft-Windows-Sysmon/Operational) detection.

Sysmon is the single highest-value optional Windows telemetry source: when
present it provides process creation with full command lines (Event 1),
network connections (3), image loads (7), CreateRemoteThread (8), process
access (10), file creation (11), registry ops (12/13), named pipes (17/18),
and process tampering (25). EVTX-ATTACK-SAMPLES is ~60% Sysmon-based, and
Sysmon Event 1 alone appears in 145 of 278 samples — so handling Sysmon
roughly doubles how many real attack techniques we can see.

Design principle — REUSE, don't duplicate: Sysmon Event 1 carries the same
"a process ran with this command line and this parent" information as
Windows Event 4688 / the live process listing, so it runs through the SAME
SUSPICIOUS_CMDLINE / suspicious-path / parent-child signatures the
processes.py detector already uses. We do NOT write per-sample rules (that
would be training on the test set and would false-positive on clean
systems); we apply the existing technique signatures to Sysmon's richer
data. Only genuinely Sysmon-specific signals (in-memory injection via
Event 8/10, named-pipe lateral movement via 17/18, process tampering via
25) get new dedicated logic, because those have no equivalent in the
built-in Windows logs at all.
"""

from __future__ import annotations
import re

from app.detection.base import SUSPICIOUS_CMDLINE, LOLBINS

# Office / browser / server processes whose child processes are suspicious —
# same set processes.py uses, kept here so the Sysmon path applies identical
# parent-child logic to Sysmon's ParentImage→Image data.
SUSPICIOUS_PARENTS = {
    "winword.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"],
    "excel.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe"],
    "outlook.exe": ["powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe"],
    "powerpnt.exe": ["powershell.exe", "cmd.exe", "wscript.exe"],
    "w3wp.exe": ["cmd.exe", "powershell.exe", "net.exe", "whoami.exe"],
    "sqlservr.exe": ["cmd.exe", "powershell.exe"],
    "mshta.exe": ["powershell.exe", "cmd.exe", "rundll32.exe"],
    "wmiprvse.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],  # WMI lateral exec
    "services.exe": ["cmd.exe", "powershell.exe"],
}

# Processes whose access to lsass.exe is a credential-dumping signal
# (Sysmon Event 10). Legitimate accessors (AV, the OS itself) are
# allowlisted to cut false positives.
LSASS_ACCESS_ALLOWLIST = {
    "wininit.exe", "services.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "svchost.exe", "msmpeng.exe", "msascuil.exe", "nissrv.exe",
    "sentinelagent.exe", "csfalconservice.exe", "cb.exe", "cbcomms.exe",
}


def _get(row, keys, default=""):
    for k in keys:
        if k in row and row[k] not in (None, ""):
            return str(row[k])
    return default


def detect_sysmon(engine, key: str, rows: list[dict]) -> None:
    # Build a PID→image map for context on later events
    pid_image = {}
    for r in rows:
        if _get(r, ["EventID"]) == "1":
            pid_image[_get(r, ["ProcessId"])] = _get(r, ["Image"]).split("\\")[-1].lower()

    for idx, row in enumerate(rows):
        eid = _get(row, ["EventID"])

        if eid == "1":
            _sysmon_process_create(engine, key, idx, row)
        elif eid == "3":
            _sysmon_network(engine, key, idx, row, pid_image)
        elif eid == "8":
            _sysmon_remote_thread(engine, key, idx, row)
        elif eid == "10":
            _sysmon_process_access(engine, key, idx, row)
        elif eid == "11":
            _sysmon_file_create(engine, key, idx, row)
        elif eid in ("17", "18"):
            _sysmon_named_pipe(engine, key, idx, row)
        elif eid == "25":
            _sysmon_process_tampering(engine, key, idx, row)
        elif eid in ("12", "13"):
            _sysmon_registry(engine, key, idx, row)
        elif eid == "6":
            _sysmon_driver_load(engine, key, idx, row)


def _sysmon_process_create(engine, key, idx, row):
    """Event 1 — reuse the full SUSPICIOUS_CMDLINE / path / parent-child stack."""
    image = _get(row, ["Image"])
    cmdline = _get(row, ["CommandLine"])
    parent_image = _get(row, ["ParentImage"])
    parent_cmd = _get(row, ["ParentCommandLine"])
    pid = _get(row, ["ProcessId"])
    name = image.split("\\")[-1].lower()
    parent_name = parent_image.split("\\")[-1].lower()
    hashes = _get(row, ["Hashes"])

    evidence = {
        "row_index": idx, "pid": pid, "name": name, "path": image,
        "cmdline": cmdline[:300], "parent": parent_name,
        "hashes": hashes[:200],
    }

    # 1) Suspicious command-line patterns (the big one — ~70 signatures)
    full_text = f"{image} {cmdline}"
    for pattern, desc, sev in SUSPICIOUS_CMDLINE:
        if re.search(pattern, full_text, re.IGNORECASE):
            engine._add_finding(
                "process_anomaly", sev,
                f"Sysmon: suspicious process command ({desc})",
                f"Process '{name}' (PID {pid}) command line exhibits {desc}. "
                f"Command: {cmdline[:200]}",
                key, evidence,
                score=80 if sev in ("critical", "high") else 50, mitre="T1059",
            )
            break  # one cmdline finding per process is enough

    # 2) Suspicious execution path
    for pattern, desc, sev in engine._check_suspicious_paths(image, proc_name=name):
        engine._add_finding(
            "process_anomaly", sev,
            f"Sysmon: process from suspicious location ({desc})",
            f"Process '{name}' (PID {pid}) ran from: {image}",
            key, evidence,
            score=60, mitre="T1036",
        )
        break

    # 3) Suspicious parent-child (Office macro, WMI exec, etc.)
    if parent_name in SUSPICIOUS_PARENTS and name in SUSPICIOUS_PARENTS[parent_name]:
        engine._add_finding(
            "process_anomaly", "high",
            f"Sysmon: suspicious parent-child ({parent_name} → {name})",
            f"'{parent_name}' spawned '{name}' (PID {pid}) — common "
            f"macro/exploit/lateral-execution pattern. Parent cmd: {parent_cmd[:150]}",
            key, evidence,
            score=80, mitre="T1566.001",
        )

    # 4) LOLBin with network/download indicators in the command
    if name in LOLBINS:
        engine.evidence_index["lolbins"].append(evidence)


def _sysmon_network(engine, key, idx, row, pid_image):
    """Event 3 — network connection. Flag suspicious ports / LOLBin-initiated conns."""
    from app.detection.network import SUSPICIOUS_PORTS
    image = _get(row, ["Image"])
    name = image.split("\\")[-1].lower()
    dport = _get(row, ["DestinationPort"])
    dip = _get(row, ["DestinationIp"])
    try:
        dport_i = int(dport) if dport else None
    except ValueError:
        dport_i = None

    evidence = {"row_index": idx, "name": name, "path": image,
                "remote": f"{dip}:{dport}", "pid": _get(row, ["ProcessId"])}

    if dport_i in SUSPICIOUS_PORTS:
        engine._add_finding(
            "network_anomaly", "high",
            f"Sysmon: connection to suspicious port {dport_i}",
            f"'{name}' connected to {dip}:{dport_i} — {SUSPICIOUS_PORTS[dport_i]}",
            key, evidence, score=70, mitre="T1571",
        )
    # LOLBin making an external network connection is inherently suspicious
    elif name in LOLBINS and dip and not dip.startswith(("127.", "::1", "0.0", "169.254", "fe80")):
        engine._add_finding(
            "network_anomaly", "high",
            f"Sysmon: LOLBin '{name}' made a network connection",
            f"Living-off-the-land binary '{name}' connected to {dip}:{dport} — "
            f"LOLBins rarely make outbound connections in normal use; common in "
            f"download-and-execute / C2 patterns.",
            key, evidence, score=70, mitre="T1105",
        )


def _sysmon_remote_thread(engine, key, idx, row):
    """Event 8 — CreateRemoteThread = classic process injection."""
    source = _get(row, ["SourceImage"]).split("\\")[-1].lower()
    target = _get(row, ["TargetImage"]).split("\\")[-1].lower()
    evidence = {"row_index": idx, "name": source, "source": source, "target": target}
    # Injection INTO lsass or a system process, or FROM an unusual source
    engine._add_finding(
        "defense_evasion", "high",
        f"Sysmon: remote thread injection ({source} → {target})",
        f"'{source}' created a remote thread in '{target}' (Event 8) — "
        f"CreateRemoteThread is a core process-injection primitive used to run "
        f"code inside another process's address space.",
        key, evidence, score=80, mitre="T1055",  # Process Injection
    )


def _sysmon_process_access(engine, key, idx, row):
    """Event 10 — process access. Access to lsass.exe = credential dumping."""
    source = _get(row, ["SourceImage"]).split("\\")[-1].lower()
    target = _get(row, ["TargetImage"]).split("\\")[-1].lower()
    access = _get(row, ["GrantedAccess"])
    call_trace = _get(row, ["CallTrace"])

    if target == "lsass.exe" and source not in LSASS_ACCESS_ALLOWLIST:
        # GrantedAccess 0x1010/0x1410/0x143a etc. = read memory (dump) rights
        evidence = {"row_index": idx, "name": source, "source": source,
                    "target": target, "granted_access": access,
                    "call_trace": call_trace[:200]}
        # Unknown/unsigned modules in the call trace strengthen the signal
        suspicious_trace = "unknown" in call_trace.lower() or "|UNKNOWN(" in call_trace
        engine._add_finding(
            "credential_access", "critical" if suspicious_trace else "high",
            f"Sysmon: lsass.exe memory access by '{source}'",
            f"'{source}' opened a handle to lsass.exe (Event 10, access {access}) — "
            f"reading lsass memory is the core of credential dumping "
            f"(Mimikatz, comsvcs MiniDump, procdump). "
            + ("Call trace contains unknown/unsigned modules, strengthening this signal."
               if suspicious_trace else "Verify the accessing process is a legitimate security tool."),
            key, evidence,
            score=90 if suspicious_trace else 78, mitre="T1003.001",  # LSASS Memory
        )


def _sysmon_file_create(engine, key, idx, row):
    """Event 11 — file creation. Flag executables/scripts dropped in suspicious paths."""
    target = _get(row, ["TargetFilename"])
    image = _get(row, ["Image"]).split("\\")[-1].lower()
    if not target:
        return
    # Only flag dropped executables/scripts in suspicious locations
    if re.search(r"\.(exe|dll|ps1|vbs|js|bat|cmd|scr|hta|jar|lnk)$", target, re.IGNORECASE):
        name = target.split("\\")[-1]
        for pattern, desc, sev in engine._check_suspicious_paths(target, proc_name=name):
            if sev in ("critical", "high", "medium"):
                engine._add_finding(
                    "execution", "medium",
                    f"Sysmon: executable/script dropped in suspicious location",
                    f"'{image}' created '{target}' ({desc}) — file drop in a "
                    f"user-writable/suspicious path.",
                    key, {"row_index": idx, "name": name, "path": target, "creator": image},
                    score=45, mitre="T1105",
                )
                break


def _sysmon_named_pipe(engine, key, idx, row):
    """Events 17/18 — named pipe create/connect. Known C2/lateral-tool pipe names."""
    pipe = _get(row, ["PipeName"])
    image = _get(row, ["Image"]).split("\\")[-1].lower()
    if not pipe:
        return
    # Named pipes used by known offensive tools (Cobalt Strike default patterns,
    # PsExec, Metasploit). These are high-signal because legit software rarely
    # uses these specific names.
    KNOWN_BAD_PIPES = [
        (r"\\?msagent_", "Cobalt Strike default pipe"),
        (r"\\?MSSE-", "Cobalt Strike named pipe"),
        (r"\\?postex_", "Cobalt Strike post-exploitation pipe"),
        (r"\\?status_", "Cobalt Strike pipe pattern"),
        (r"\\?psexesvc", "PsExec service pipe"),
        (r"\\?paexec", "PAExec pipe"),
        (r"\\?remcom_", "RemCom lateral tool pipe"),
        (r"\\?csexecsvc", "CSExec pipe"),
        (r"\\?\d{4,}", "Metasploit-style numeric pipe"),
    ]
    for pattern, desc in KNOWN_BAD_PIPES:
        if re.search(pattern, pipe, re.IGNORECASE):
            engine._add_finding(
                "lateral_movement", "high",
                f"Sysmon: suspicious named pipe ({desc})",
                f"'{image}' used named pipe '{pipe}' — matches {desc}. Named pipes "
                f"are used by lateral-movement and C2 frameworks for inter-process "
                f"and remote communication.",
                key, {"row_index": idx, "name": image, "pipe": pipe},
                score=72, mitre="T1021.002",
            )
            break


def _sysmon_process_tampering(engine, key, idx, row):
    """Event 25 — process tampering (process hollowing / herpaderping)."""
    image = _get(row, ["Image"])
    name = image.split("\\")[-1].lower()
    ttype = _get(row, ["Type"])
    engine._add_finding(
        "defense_evasion", "high",
        f"Sysmon: process tampering detected ({ttype})",
        f"Process '{name}' was tampered with (Event 25, type '{ttype}') — "
        f"indicates process hollowing or herpaderping, where a legitimate "
        f"process image is replaced in memory to disguise malicious code.",
        key, {"row_index": idx, "name": name, "path": image, "tamper_type": ttype},
        score=82, mitre="T1055.012",  # Process Hollowing
    )


def _sysmon_registry(engine, key, idx, row):
    """Events 12/13 — registry. Flag autorun/persistence key modifications."""
    target = _get(row, ["TargetObject"])
    image = _get(row, ["Image"]).split("\\")[-1].lower()
    details = _get(row, ["Details"])
    if not target:
        return
    AUTORUN_MARKERS = (
        "\\currentversion\\run", "\\currentversion\\runonce",
        "\\winlogon\\shell", "\\winlogon\\userinit",
        "\\image file execution options", "\\appinit_dlls",
        "\\currentversion\\policies\\explorer\\run",
        "\\services\\", "\\currentcontrolset\\services",
    )
    tl = target.lower()
    if any(m in tl for m in AUTORUN_MARKERS):
        engine._add_finding(
            "persistence", "medium",
            f"Sysmon: autorun/persistence registry modification",
            f"'{image}' modified registry key '{target}'"
            + (f" = {details[:100]}" if details else "")
            + " — a known autostart/persistence location.",
            key, {"row_index": idx, "name": image, "key": target, "value": details[:200]},
            score=55, mitre="T1547.001",
        )


def _sysmon_driver_load(engine, key, idx, row):
    """Event 6 — driver load. Flag unsigned drivers (BYOVD attacks)."""
    image = _get(row, ["ImageLoaded"])
    signed = _get(row, ["Signed"]).lower()
    signature = _get(row, ["Signature"])
    name = image.split("\\")[-1].lower() if image else ""
    if signed == "false":
        engine._add_finding(
            "privilege_escalation", "high",
            f"Sysmon: unsigned driver loaded ({name})",
            f"Unsigned driver '{image}' was loaded (Event 6) — unsigned/untrusted "
            f"drivers are the core of Bring-Your-Own-Vulnerable-Driver (BYOVD) "
            f"attacks used to disable security tools or gain kernel execution.",
            key, {"row_index": idx, "name": name, "path": image, "signature": signature},
            score=75, mitre="T1068",
        )
