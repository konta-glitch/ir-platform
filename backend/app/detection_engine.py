"""
Detection Engine — forensic analysis of ALL collected data.

This is the core analytical layer that runs BEFORE the LLM. It processes
every single row (not a sample) using DFIR detection rules, then produces
a prioritized set of findings with evidence pointers for the LLM to reason about.

Philosophy: The LLM should never have to "guess" from a sample. The detection
engine examines everything, flags what matters, and hands the LLM a complete
picture of suspicious activity with full context and evidence references.

Detection categories:
  - Process anomalies (LOLBins, encoded commands, suspicious paths, masquerading)
  - Network anomalies (C2 ports, suspicious destinations, beaconing patterns)
  - Persistence (services, tasks, registry, startup, WMI)
  - Execution evidence (prefetch, amcache anomalies)
  - Credential access patterns
  - Lateral movement indicators
  - Defense evasion (log clearing, obfuscation)
  - Behavioral correlation across artifacts
"""

import re
import logging
from collections import defaultdict, Counter
from datetime import datetime
from typing import Any

from app.detection_extended import detect_shimcache, detect_userassist, detect_shellbags

logger = logging.getLogger(__name__)

# Bump this whenever detection/sigma/correlation logic changes materially.
# It's stamped into every analysis so a report makes clear which engine
# produced it — and stale incidents (analyzed by an older build, then
# re-viewed) are obvious instead of looking like a current result.
ENGINE_VERSION = "2026.06.19-shimcache-userassist-shellbags"


# ══════════════════════════════════════════════════
# Detection signatures
# ══════════════════════════════════════════════════

# Living-off-the-land binaries frequently abused
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
    "msiexec.exe", "scriptrunner.exe", "forfiles.exe", "pcalua.exe", "syncappvpublishingserver.exe",
    "schtasks.exe", "at.exe", "sc.exe", "net.exe", "net1.exe", "reg.exe",
    "vssadmin.exe", "wevtutil.exe", "fsutil.exe", "cipher.exe", "takeown.exe",
    "psexec.exe", "psexesvc.exe", "wsmprovhost.exe", "winrs.exe",
}

# Suspicious command-line patterns (regex)
SUSPICIOUS_CMDLINE = [
    (r"-enc(?:odedcommand)?\s+[A-Za-z0-9+/]{20,}", "PowerShell encoded command", "high"),
    (r"-e\s+[A-Za-z0-9+/]{20,}", "PowerShell encoded command (short flag)", "high"),
    (r"FromBase64String", "Base64 decoding in command", "high"),
    (r"-w(?:indowstyle)?\s+hidden", "Hidden window", "medium"),
    (r"-nop|-noprofile", "PowerShell no-profile", "medium"),
    (r"-noni|-noninteractive", "PowerShell non-interactive", "medium"),
    (r"\bIEX\b|Invoke-Expression", "PowerShell Invoke-Expression", "high"),
    (r"DownloadString|DownloadFile|DownloadData", "Remote download", "high"),
    (r"Net\.WebClient|Invoke-WebRequest|\bwget\b|curl\s+http", "Web request in command", "medium"),
    (r"-ExecutionPolicy\s+(bypass|unrestricted)|\bbypass\b\s+-", "Execution policy bypass", "medium"),
    (r"hidden.*FromBase64|FromBase64.*hidden", "Hidden + encoded", "critical"),
    (r"certutil.*-decode|certutil.*-urlcache", "Certutil abuse", "high"),
    (r"bitsadmin.*\/transfer", "BITS transfer (download)", "high"),
    (r"regsvr32.*\/i:http|regsvr32.*scrobj", "Regsvr32 scriptlet (Squiblydoo)", "critical"),
    (r"mshta.*http|mshta.*javascript|mshta.*vbscript", "MSHTA remote/script", "high"),
    (r"rundll32.*javascript|rundll32.*url\.dll", "Rundll32 abuse", "high"),
    (r"vssadmin.*delete|wmic.*shadowcopy.*delete", "Shadow copy deletion", "critical"),
    (r"wevtutil.*cl|wevtutil.*clear-log", "Event log clearing", "critical"),
    (r"wbadmin.*delete", "Backup deletion", "critical"),
    (r"bcdedit.*recoveryenabled.*no|bcdedit.*bootstatuspolicy", "Boot config tampering", "high"),
    (r"net\s+user\s+\/add|net\s+localgroup.*\/add", "Account/group manipulation", "high"),
    (r"schtasks.*\/create", "Scheduled task creation", "medium"),
    (r"reg\s+add.*\\Run|reg\s+add.*CurrentVersion\\Run", "Registry run key addition", "high"),
    (r"-ExecutionPolicy\s+Bypass.*-File.*\\(Temp|AppData|ProgramData)", "Script from suspicious path", "high"),
    (r"\\\\.*\\(C\$|ADMIN\$|IPC\$)", "Admin share access", "medium"),
    # Credential access
    (r"mimikatz|sekurlsa|lsadump|kerberos::|crypto::", "Mimikatz/credential dumping", "critical"),
    (r"comsvcs\.dll.*MiniDump|rundll32.*MiniDump", "LSASS memory dump (comsvcs)", "critical"),
    (r"procdump.*lsass|procdump.*-ma", "ProcDump on LSASS", "critical"),
    (r"reg\s+save.*\\SAM|reg\s+save.*\\SYSTEM|reg\s+save.*\\SECURITY", "Registry hive dump (creds)", "critical"),
    (r"ntdsutil|ntds\.dit", "NTDS.dit extraction (domain creds)", "critical"),
    (r"vaultcmd|vault::|CredentialManager", "Windows Credential Manager access", "high"),
    # Browser credential / session theft — the typical path to account takeover
    # (stolen cookies/tokens let an attacker hijack a Gmail/Workspace session
    # without ever needing the password).
    (r"\\User Data\\.*\\Login Data|\\User Data\\.*\\Cookies|\\User Data\\.*\\Web Data",
     "Browser credential/cookie store access", "high"),
    (r"\\Login Data\b|\\Cookies\b|\\Network\\Cookies", "Browser saved-password/cookie DB access", "high"),
    (r"sqlite.*(Login Data|Cookies|Web Data)|(Login Data|Cookies).*sqlite",
     "Browser credential DB read via SQLite", "high"),
    (r"redline|raccoon|lumma|vidar|stealc|meta\s?stealer|aurora\s?stealer|mars\s?stealer|"
     r"azorult|formbook|agent\s?tesla", "Known infostealer malware family", "critical"),
    (r"\\Local State\b.*encrypted_key|os_crypt|DPAPI.*Chrome|Chrome.*masterkey",
     "Browser master key (DPAPI) theft — cookie decryption", "critical"),
    (r"(token|cookie|credential)s?\.(txt|json|sqlite|db).*(upload|exfil|post)|"
     r"grab.*(cookie|password|token)", "Credential/cookie exfiltration", "critical"),
    (r"\\Microsoft\\Edge\\User Data|\\BraveSoftware\\.*\\User Data|"
     r"\\Mozilla\\Firefox\\Profiles.*\.(sqlite|db)", "Browser profile credential access", "high"),
    # Lateral movement
    (r"psexec|paexec|csexec", "PsExec lateral movement", "high"),
    (r"wmic.*\/node:|wmic.*process call create", "WMIC remote execution", "high"),
    (r"Invoke-Command.*-ComputerName|Enter-PSSession", "PowerShell remoting", "medium"),
    (r"sc\s+\\\\|sc.exe\s+\\\\", "Remote service creation", "high"),
    (r"at\s+\\\\|schtasks.*\/s\s+", "Remote scheduled task", "high"),
    (r"wmiexec|smbexec|atexec|dcomexec", "Impacket lateral tool", "critical"),
    # Remote-access / RMM tooling — a leading vector for account takeover and
    # persistent remote control. Often abused (or attacker-installed) to keep
    # access. Medium by default because some are legitimately deployed; the
    # path (temp/programdata) and rarity raise the real signal.
    (r"anydesk|teamviewer|screenconnect|connectwise|splashtop|gotoassist|"
     r"logmein|remotepc|ammyy|ultraviewer|atera|syncro|datto\s?rmm|"
     r"kaseya|n-?able|pulseway|jwrapper.*remote|netlock.*rmm|action1|"
     r"dwagent|dwservice|rustdesk|meshagent|mesh\s?central|tacticalrmm|"
     r"_rmm_|\\rmm\\|rmm_agent|rmm_v\d", "Remote access / RMM tool present", "medium"),
    # Exfiltration / staging
    (r"Compress-Archive|makecab|7z\s+a|rar\s+a|winrar", "Archive creation (staging)", "medium"),
    (r"Invoke-WebRequest.*-Method\s+Put|curl.*-T\s|curl.*--upload", "Data upload", "high"),
    (r"ftp\s+-s:|Net\.WebClient.*UploadFile", "FTP/web upload", "high"),
    (r"nslookup.*-type=txt|dns.*exfil", "Possible DNS exfiltration", "high"),
    # Ransomware indicators
    (r"cipher\s+\/w|sdelete", "Secure deletion (anti-recovery)", "high"),
    (r"\.locked|\.encrypted|\.crypt|README.*DECRYPT|HOW.*DECRYPT", "Ransomware artifacts", "critical"),
    (r"taskkill.*\/f.*\/im.*(sql|oracle|exchange|backup)", "Killing business services (ransomware)", "high"),
    (r"wmic.*shadowcopy.*delete|vssadmin.*delete\s+shadows", "Shadow copy deletion (ransomware)", "critical"),
    # Defense evasion
    (r"Set-MpPreference.*-Disable|Add-MpPreference.*-Exclusion", "Windows Defender tampering", "high"),
    (r"netsh.*firewall.*disable|netsh advfirewall set.*state\s+off", "Firewall disabled", "high"),
    (r"Set-ExecutionPolicy.*Unrestricted|Set-ExecutionPolicy.*Bypass", "Execution policy weakened", "medium"),
    (r"attrib.*\+h|attrib.*\+s", "Hiding files (attrib)", "low"),
    (r"timestomp|SetFileTime|\$STANDARD_INFORMATION", "Timestamp manipulation", "high"),
    (r"fodhelper|computerdefaults|sdclt|eventvwr.*reg", "UAC bypass technique", "high"),
    # Discovery
    (r"whoami\s+\/priv|whoami\s+\/groups", "Privilege enumeration", "low"),
    (r"net\s+group.*\/domain|net\s+user.*\/domain", "Domain enumeration", "medium"),
    (r"nltest|dsquery|adfind", "AD reconnaissance", "medium"),
    (r"Get-ADUser|Get-ADComputer|Get-DomainUser", "PowerView/AD enum", "medium"),
    (r"arp\s+-a|route\s+print|ipconfig\s+\/all", "Network discovery", "low"),
]

# Suspicious file paths (process running from these = suspicious)
SUSPICIOUS_PATHS = [
    (r"\\Temp\\", "Running from Temp", "medium"),
    (r"\\AppData\\Local\\Temp\\", "Running from user Temp", "medium"),
    (r"\\AppData\\Roaming\\", "Running from Roaming AppData", "low"),
    (r"\\ProgramData\\", "Running from ProgramData", "low"),
    (r"\\Users\\Public\\", "Running from Public", "medium"),
    (r"\\Downloads\\", "Running from Downloads", "medium"),
    (r"\\Windows\\Temp\\", "Running from Windows Temp", "medium"),
    (r"\\\$Recycle\.Bin\\", "Running from Recycle Bin", "high"),
    (r"\\PerfLogs\\", "Running from PerfLogs", "medium"),
    (r"C:\\Windows\\[^\\]+\.exe", "Executable directly in Windows root", "medium"),
]

# Binaries Microsoft ships directly in C:\Windows\ (not System32/SysWOW64) by
# default on every install. The SUSPICIOUS_PATHS regex above can't tell these
# apart from a genuinely planted binary dropped in the same location — both
# match "C:\Windows\<name>.exe" — so this allowlist exists to suppress the
# known-legitimate set while still flagging anything NOT on this list.
# explorer.exe in particular was firing as a false positive on every single
# collection, since it legitimately lives at C:\Windows\explorer.exe on every
# Windows machine that has ever booted.
WINDOWS_ROOT_ALLOWLIST = {
    "explorer.exe", "notepad.exe", "regedit.exe", "write.exe",
    "hh.exe", "winhlp32.exe", "splwow64.exe", "bfsvc.exe",
    "twunk_16.exe", "twunk_32.exe", "ssvagent.exe",
}

# Process masquerading — system process names that should run from System32
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

# Known suspicious ports (C2, common malware)
SUSPICIOUS_PORTS = {
    4444: "Metasploit default", 5555: "Common backdoor",
    1337: "Common backdoor", 31337: "Back Orifice",
    6666: "Common IRC bot", 6667: "IRC",
    8080: "Common HTTP proxy/C2", 8443: "Alt HTTPS/C2",
    9001: "Tor", 9050: "Tor SOCKS",
    1080: "SOCKS proxy", 3389: "RDP (lateral movement)",
    5985: "WinRM HTTP", 5986: "WinRM HTTPS",
}

# High-value Windows Event IDs and their meaning
EVENT_ID_MEANINGS = {
    4624: ("Successful logon", "low"),
    4625: ("Failed logon", "medium"),
    4634: ("Logoff", "info"),
    4648: ("Logon with explicit credentials (runas)", "medium"),
    4672: ("Special privileges assigned", "medium"),
    4688: ("Process creation", "low"),
    4697: ("Service installed", "high"),
    4698: ("Scheduled task created", "high"),
    4699: ("Scheduled task deleted", "medium"),
    4700: ("Scheduled task enabled", "medium"),
    4702: ("Scheduled task updated", "medium"),
    4720: ("User account created", "high"),
    4722: ("User account enabled", "medium"),
    4724: ("Password reset attempt", "medium"),
    4728: ("Member added to global group", "high"),
    4732: ("Member added to local group", "high"),
    4756: ("Member added to universal group", "high"),
    4625: ("Failed logon", "medium"),
    1102: ("Audit log cleared", "critical"),
    7045: ("Service installed (System)", "high"),
    7040: ("Service start type changed", "medium"),
    104: ("Event log cleared", "critical"),
    4103: ("PowerShell module logging", "low"),
    4104: ("PowerShell script block", "medium"),
    1: ("Sysmon: Process creation", "low"),
    3: ("Sysmon: Network connection", "low"),
    7: ("Sysmon: Image loaded", "low"),
    8: ("Sysmon: CreateRemoteThread", "high"),
    11: ("Sysmon: File created", "low"),
    13: ("Sysmon: Registry value set", "low"),
    22: ("Sysmon: DNS query", "low"),
}

# Account/logon anomaly thresholds
BRUTE_FORCE_THRESHOLD = 5  # failed logons from same source


class DetectionEngine:
    """Runs comprehensive forensic detection across all collected artifacts."""

    def __init__(self):
        self.findings: list[dict] = []
        self.stats: dict = defaultdict(int)
        self.evidence_index: dict[str, list] = defaultdict(list)

    @staticmethod
    def _check_suspicious_paths(path: str, proc_name: str = ""):
        """
        Yield (pattern, desc, sev) for every SUSPICIOUS_PATHS rule that
        matches `path`, EXCEPT the "Executable directly in Windows root"
        rule when `proc_name` is on WINDOWS_ROOT_ALLOWLIST.

        Centralizing this in one place (instead of repeating the allowlist
        check at all 6 call sites) means the fix can't accidentally be
        applied at some call sites and missed at others.
        """
        name_lower = proc_name.lower().split("\\")[-1] if proc_name else ""
        for pattern, desc, sev in SUSPICIOUS_PATHS:
            if desc == "Executable directly in Windows root" and name_lower in WINDOWS_ROOT_ALLOWLIST:
                continue
            if re.search(pattern, path, re.IGNORECASE):
                yield pattern, desc, sev

    def analyze(self, data: dict, progress_cb=None) -> dict:
        """
        Analyze ALL data and return prioritized findings with evidence.

        progress_cb(artifact_name, processed_rows, total_rows) is called
        per artifact so the caller can stream live progress.
        """
        self.findings = []
        self.stats = defaultdict(int)
        self.evidence_index = defaultdict(list)

        # Strip metadata
        metadata = data.get("_metadata", {})

        # Total rows for progress
        artifacts = [(k, v) for k, v in data.items()
                     if not k.startswith("_") and isinstance(v, list)]
        total_all = sum(len(v) for _, v in artifacts) or 1
        processed_all = 0

        # Run detections per artifact type
        for key, rows in artifacts:
            self.stats[f"{key}_total_rows"] = len(rows)
            key_lower = key.lower()

            if progress_cb:
                progress_cb(key, processed_all, total_all)

            # Route to appropriate detector based on artifact type
            if any(t in key_lower for t in ["pslist", "process", "pstree"]):
                self._detect_processes(key, rows)
            elif any(t in key_lower for t in ["netstat", "network", "connection"]):
                self._detect_network(key, rows)
            elif any(t in key_lower for t in ["service", "executable"]):
                self._detect_services(key, rows)
            elif any(t in key_lower for t in ["scheduledtask", "task", "command"]):
                self._detect_tasks(key, rows)
            elif any(t in key_lower for t in ["evtx", "eventlog", "event", "logon"]):
                self._detect_eventlogs(key, rows)
            # NOTE: shimcache/userassist/shellbags must be checked BEFORE the
            # generic "prefetch|amcache" / "registry" branches below, since
            # those substring checks would otherwise swallow them (e.g.
            # "shimcache" contains no overlap today, but "userassist" keys
            # sometimes ship as "registry_userassist" from collectors).
            elif "shimcache" in key_lower or "appcompatcache" in key_lower:
                detect_shimcache(self._add_finding, key, rows)
            elif "userassist" in key_lower:
                detect_userassist(self._add_finding, key, rows)
            elif "shellbag" in key_lower:
                detect_shellbags(self._add_finding, key, rows)
            elif any(t in key_lower for t in ["prefetch", "amcache"]):
                self._detect_execution(key, rows)
            elif any(t in key_lower for t in ["registry", "run", "autorun", "startup"]):
                self._detect_persistence_registry(key, rows)
            elif any(t in key_lower for t in ["lnk", "shortcut"]):
                self._detect_lnk(key, rows)
            elif any(t in key_lower for t in ["searchglobs", "matches", "metadata", "upload"]):
                self._detect_file_anomalies(key, rows)
            else:
                self._detect_generic(key, rows)

            processed_all += len(rows)
            if progress_cb:
                progress_cb(key, processed_all, total_all)

        # Behavioral correlation across all findings
        behavioral = self._correlate_behavior()

        # Enrich each finding's evidence with the source file path, so the
        # report can point to "this IOC came from <file> at row N".
        self._enrich_source_files(data)

        # Deduplicate: collapse identical repeated findings into one with an
        # occurrence count. A host that cleared its log 50 times is ONE finding
        # ("×50"), not 50 criticals flooding the report.
        self._deduplicate_findings()

        # Sort findings by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.findings.sort(key=lambda f: (sev_order.get(f["severity"], 5), -f.get("score", 0)))

        # Build a coverage report — IR defensibility: prove every row scanned
        coverage = {
            "artifacts_scanned": len(artifacts),
            "total_rows_scanned": total_all if total_all != 1 else sum(len(v) for _, v in artifacts),
            "per_artifact": [
                {"artifact": k, "rows_scanned": len(v), "fully_scanned": True}
                for k, v in sorted(artifacts, key=lambda x: -len(x[1]))
            ],
        }

        return {
            "findings": self.findings,
            "statistics": dict(self.stats),
            "behavioral_summary": behavioral,
            "coverage": coverage,
            "total_findings": len(self.findings),
            "critical_count": sum(1 for f in self.findings if f["severity"] == "critical"),
            "high_count": sum(1 for f in self.findings if f["severity"] == "high"),
            "medium_count": sum(1 for f in self.findings if f["severity"] == "medium"),
            "engine_version": ENGINE_VERSION,
            "analyzed_at": datetime.utcnow().isoformat(),
        }

    def _deduplicate_findings(self):
        """
        Collapse identical repeated findings into one with an occurrence count.

        Two findings are 'the same' if they share title + category + severity +
        MITRE + the same artifact. We keep the first occurrence, attach the
        total count and a sample of locators, and drop the rest. This turns
        '500 × Audit log cleared' into a single finding with occurrences=500.
        """
        seen: dict = {}
        deduped = []
        for f in self.findings:
            key = (
                f.get("title", ""), f.get("category", ""),
                f.get("severity", ""), f.get("mitre", ""),
                f.get("artifact", ""),
            )
            if key in seen:
                first = seen[key]
                first["occurrences"] = first.get("occurrences", 1) + 1
                # Keep up to 10 sample locators for evidence
                locs = first.setdefault("occurrence_locators", [])
                loc = f.get("evidence", {}).get("locator")
                if loc and len(locs) < 10:
                    locs.append(loc)
            else:
                f["occurrences"] = 1
                seen[key] = f
                deduped.append(f)

        collapsed = len(self.findings) - len(deduped)
        if collapsed > 0:
            logger.info(f"Deduplicated {len(self.findings)} → {len(deduped)} findings "
                        f"({collapsed} duplicates collapsed)")
        self.findings = deduped

    def _enrich_source_files(self, data: dict):
        """Add the originating file path to each finding's evidence."""
        from urllib.parse import unquote
        for finding in self.findings:
            ev = finding.get("evidence", {})
            artifact = finding.get("artifact", "")
            row_idx = ev.get("row_index")
            if artifact in data and isinstance(row_idx, int):
                rows = data[artifact]
                if 0 <= row_idx < len(rows) and isinstance(rows[row_idx], dict):
                    src = rows[row_idx].get("_source_file")
                    if src:
                        # Decode URL-encoded paths for readability
                        ev["source_file"] = unquote(str(src)).replace("%2F", "/")
            if ev.get("source_file"):
                ev["locator"] = f"{ev['source_file']} (row {row_idx})"
            elif row_idx is not None:
                ev["locator"] = f"{artifact} (row {row_idx})"

    def _add_finding(self, category: str, severity: str, title: str,
                     description: str, artifact: str, evidence: dict,
                     score: int = 0, mitre: str = ""):
        """Record a finding with evidence pointer."""
        finding_id = f"F{len(self.findings) + 1:04d}"
        self.findings.append({
            "id": finding_id,
            "category": category,
            "severity": severity,
            "title": title,
            "description": description,
            "artifact": artifact,
            "evidence": evidence,
            "score": score,
            "mitre": mitre,
        })
        self.stats[f"detections_{severity}"] += 1

    # ── Process detection ──

    def _detect_processes(self, key: str, rows: list[dict]):
        # Build PID → name map for parent-child analysis
        pid_map = {}
        for proc in rows:
            pid = self._get(proc, ["Pid", "pid", "ProcessId", "PID"])
            name = self._get(proc, ["Name", "name", "ProcessName"]).lower()
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
            name = self._get(proc, ["Name", "name", "ProcessName", "Exe"]).lower()
            path = self._get(proc, ["Exe", "Path", "path", "CommandLine", "ExecutablePath"])
            cmdline = self._get(proc, ["CommandLine", "cmdline", "Cmd"])
            pid = self._get(proc, ["Pid", "pid", "ProcessId", "PID"])
            ppid = self._get(proc, ["Ppid", "ppid", "ParentProcessId", "PPID"])

            evidence_base = {
                "row_index": idx, "pid": pid, "ppid": ppid,
                "name": name, "path": path, "cmdline": cmdline[:300],
            }

            # Parent-child anomaly
            parent_name = pid_map.get(str(ppid), "")
            if parent_name in suspicious_parents:
                child_base = name.split("\\")[-1]
                if child_base in suspicious_parents[parent_name]:
                    self._add_finding(
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
                    self._add_finding(
                        "process_anomaly", sev,
                        f"Suspicious process command: {desc}",
                        f"Process '{name}' (PID {pid}) exhibits {desc}. Command: {cmdline[:200]}",
                        key, evidence_base,
                        score=80 if sev in ("critical", "high") else 50,
                        mitre="T1059",
                    )

            # Check suspicious paths
            for pattern, desc, sev in self._check_suspicious_paths(path, proc_name=name):
                self._add_finding(
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
                    self._add_finding(
                        "process_anomaly", "critical",
                        f"Process masquerading: {name} from wrong path",
                        f"System process '{name}' should run from System32 but runs from: {path}",
                        key, evidence_base,
                        score=95, mitre="T1036.005",
                    )

            # LOLBin usage tracking
            if name in LOLBINS and cmdline:
                self.evidence_index["lolbins"].append(evidence_base)

    # ── Network detection ──

    def _detect_network(self, key: str, rows: list[dict]):
        remote_counter = Counter()
        for idx, conn in enumerate(rows):
            raddr = self._get(conn, ["Raddr", "RemoteAddress", "remote", "remote_address", "ForeignAddress"])
            laddr = self._get(conn, ["Laddr", "LocalAddress", "local", "local_address"])
            state = self._get(conn, ["Status", "State", "state"])
            pid = self._get(conn, ["Pid", "pid", "OwningProcess"])
            proc = self._get(conn, ["Name", "Process", "process_name"])

            # Extract remote port
            rport = None
            port_match = re.search(r":(\d+)$", str(raddr))
            if port_match:
                rport = int(port_match.group(1))

            evidence = {
                "row_index": idx, "local": laddr, "remote": raddr,
                "state": state, "pid": pid, "process": proc,
            }

            if rport in SUSPICIOUS_PORTS:
                self._add_finding(
                    "network_anomaly", "high",
                    f"Connection to suspicious port {rport}",
                    f"Process '{proc}' (PID {pid}) connected to {raddr} — {SUSPICIOUS_PORTS[rport]}",
                    key, evidence,
                    score=70, mitre="T1571",  # Non-Standard Port
                )

            # Track remote addresses for beaconing detection
            if raddr and "ESTABLISHED" in str(state).upper():
                ip_only = re.sub(r":\d+$", "", str(raddr))
                if ip_only and not ip_only.startswith(("127.", "0.0", "::", "[::")):
                    remote_counter[ip_only] += 1

        # Beaconing: many connections to same remote
        for ip, count in remote_counter.most_common(10):
            if count >= 5:
                self._add_finding(
                    "network_anomaly", "medium",
                    f"Potential beaconing to {ip}",
                    f"{count} connections to the same remote host {ip} — possible C2 beaconing",
                    key, {"remote": ip, "connection_count": count},
                    score=55, mitre="T1071",  # Application Layer Protocol
                )

    # ── Service detection ──

    # Known-good service binaries (signed Windows / common vendor software)
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

    def _is_known_good_service(self, name, path_l: str) -> bool:
        """Heuristic allowlist for benign Windows/vendor services."""
        if name and str(name).lower() in self.KNOWN_GOOD_SERVICE_NAMES:
            return True
        # System32 msiexec, svchost etc. are normal service hosts
        if any(g in path_l for g in self.KNOWN_GOOD_SERVICE_PATHS):
            # ...unless the command line carries an obviously malicious payload
            if not re.search(r"-enc\b|frombase64|downloadstring|iex\s*\(", path_l):
                return True
        return False

    def _detect_services(self, key: str, rows: list[dict]):
        for idx, svc in enumerate(rows):
            name = self._get(svc, ["Name", "name", "ServiceName", "DisplayName"])
            path = self._get(svc, ["PathName", "ImagePath", "image_path", "Exe", "path", "CommandLine"])
            account = self._get(svc, ["StartName", "account", "ServiceAccount"])
            start = self._get(svc, ["StartMode", "start_type", "StartType"])

            if not path:
                continue
            path_l = str(path).lower()

            evidence = {
                "row_index": idx, "name": name, "path": path,
                "account": account, "start_mode": start,
            }

            # Skip well-known legitimate Windows/system service binaries to
            # cut false positives (msiexec, svchost, .NET, Defender, etc.).
            if self._is_known_good_service(name, path_l):
                continue

            # Service binary in suspicious location — respect the PATTERN's
            # own severity instead of forcing "high". ProgramData alone is
            # 'low' (lots of legit software lives there), not high.
            bin_name = str(path).split("\\")[-1].split(" ")[0]
            for pattern, desc, sev in self._check_suspicious_paths(path, proc_name=bin_name):
                # Only flag medium+ path findings for services; 'low'
                # locations like ProgramData are too noisy on their own.
                if sev in ("critical", "high", "medium"):
                    self._add_finding(
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
                    self._add_finding(
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
                    self._add_finding(
                        "persistence", "medium",
                        "Unquoted service path",
                        f"Service '{name}' has unquoted path with spaces: {path} — privilege escalation risk",
                        key, evidence,
                        score=40, mitre="T1574.009",
                    )

    # ── Scheduled task detection ──

    def _detect_tasks(self, key: str, rows: list[dict]):
        for idx, task in enumerate(rows):
            name = self._get(task, ["Name", "name", "TaskName"])
            command = self._get(task, ["Command", "command", "Action", "Exe", "Arguments"])
            args = self._get(task, ["Arguments", "args", "Args"])

            full = f"{command} {args}"
            evidence = {
                "row_index": idx, "name": name, "command": command, "args": args[:200],
            }

            for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                if re.search(pattern, full, re.IGNORECASE):
                    self._add_finding(
                        "persistence", sev,
                        f"Scheduled task with suspicious command: {desc}",
                        f"Task '{name}' exhibits {desc}: {full[:200]}",
                        key, evidence,
                        score=80, mitre="T1053.005",  # Scheduled Task
                    )

            task_bin_name = str(command).split("\\")[-1].split(" ")[0]
            for pattern, desc, sev in self._check_suspicious_paths(full, proc_name=task_bin_name):
                self._add_finding(
                    "persistence", "medium",
                    f"Scheduled task references suspicious path",
                    f"Task '{name}' references {desc}: {full[:200]}",
                    key, evidence,
                    score=50, mitre="T1053.005",
                )

    # ── Event log detection ──

    def _detect_eventlogs(self, key: str, rows: list[dict]):
        failed_logons = defaultdict(list)
        event_id_counts = Counter()
        new_accounts = []
        cleared_logs = []

        for idx, event in enumerate(rows):
            eid = self._get(event, ["EventID", "event_id", "Id", "ID"])
            try:
                eid = int(eid) if eid else None
            except (ValueError, TypeError):
                eid = None

            if eid is None:
                continue

            event_id_counts[eid] += 1
            data_str = str(event)[:500]
            timestamp = self._get(event, ["TimeCreated", "timestamp", "Timestamp", "time"])

            evidence = {
                "row_index": idx, "event_id": eid, "timestamp": timestamp,
                "data": data_str,
            }

            # Log-clearing events — but ONLY in the channels where they mean
            # "audit log cleared". Event 104 in particular is overloaded:
            #   - System/Security channel 104/1102 = real log clear (critical)
            #   - Diagnosis-Scripted, PowerShell, and many app channels emit
            #     Event 104 for benign reasons (scenario completion, etc.)
            # Flagging 104 everywhere produced hundreds of false positives.
            channel = str(self._get(event, ["Channel", "channel", "LogName"]) or "").lower()
            source = str(self._get(event, ["provider", "Provider", "SourceName"]) or "").lower()
            is_security_channel = (
                "security" in channel or "system" in channel
                or "eventlog" in source or "eventlog" in channel
                or key.lower().endswith("security") or key.lower().endswith("system")
                or "evtx_security" in key.lower() or "evtx_system" in key.lower()
            )

            if eid == 1102 and ("security" in channel or "evtx_security" in key.lower()
                                or key.lower().endswith("security") or not channel):
                # 1102 is Security-log specific — the audit log was cleared
                cleared_logs.append(evidence)
                self._add_finding(
                    "defense_evasion", "critical",
                    "Security audit log cleared",
                    f"Event 1102 — the Security audit log was cleared at {timestamp}. "
                    f"Strong indicator of anti-forensic activity.",
                    key, evidence,
                    score=95, mitre="T1070.001",
                )
            elif eid == 104 and is_security_channel:
                # 104 only counts as a clear in System/Security/EventLog channels
                cleared_logs.append(evidence)
                self._add_finding(
                    "defense_evasion", "high",
                    "Event log cleared",
                    f"Event 104 in {channel or key} — an event log was cleared at "
                    f"{timestamp}. Possible anti-forensic activity.",
                    key, evidence,
                    score=75, mitre="T1070.001",
                )
            # Event 104 in any other channel (Diagnosis-Scripted, etc.) is
            # routine and intentionally NOT flagged.

            elif eid == 4720:  # New account
                new_accounts.append(evidence)
                self._add_finding(
                    "persistence", "high",
                    "New user account created",
                    f"Event 4720 — a user account was created at {timestamp}",
                    key, evidence,
                    score=70, mitre="T1136.001",  # Create Account
                )

            elif eid in (4728, 4732, 4756):  # Added to privileged group
                self._add_finding(
                    "privilege_escalation", "high",
                    "Account added to privileged group",
                    f"Event {eid} — a member was added to a security group at {timestamp}",
                    key, evidence,
                    score=70, mitre="T1098",  # Account Manipulation
                )

            elif eid in (4697, 7045):  # Service installed
                # Service installs are routine on Windows (updates, drivers,
                # software). Default to medium; only escalate to high if the
                # service binary/command looks suspicious.
                svc_sev, svc_score = "medium", 50
                if re.search(r"-enc\b|frombase64|downloadstring|\biex\b|"
                             r"\\temp\\|\\appdata\\|powershell.*-w\s+hidden",
                             data_str, re.IGNORECASE):
                    svc_sev, svc_score = "high", 75
                self._add_finding(
                    "persistence", svc_sev,
                    "New service installed",
                    f"Event {eid} — a new service was installed at {timestamp}. Data: {data_str[:200]}",
                    key, evidence,
                    score=svc_score, mitre="T1543.003",
                )

            elif eid in (4698, 4702):  # Scheduled task
                self._add_finding(
                    "persistence", "medium",
                    "Scheduled task created/modified",
                    f"Event {eid} — scheduled task activity at {timestamp}",
                    key, evidence,
                    score=55, mitre="T1053.005",
                )

            elif eid == 4625:  # Failed logon
                # Extract source
                src = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", data_str)
                src_ip = src.group(1) if src else "unknown"
                failed_logons[src_ip].append(evidence)

            elif eid == 4104:  # PowerShell script block
                # Check for suspicious content in script block
                for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                    if re.search(pattern, data_str, re.IGNORECASE):
                        self._add_finding(
                            "execution", sev,
                            f"Suspicious PowerShell script block: {desc}",
                            f"Event 4104 at {timestamp} — script block contains {desc}",
                            key, evidence,
                            score=75, mitre="T1059.001",
                        )
                        break

            elif eid == 4688:  # Process creation
                for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                    if re.search(pattern, data_str, re.IGNORECASE):
                        self._add_finding(
                            "execution", sev,
                            f"Suspicious process creation: {desc}",
                            f"Event 4688 at {timestamp} — process with {desc}",
                            key, evidence,
                            score=70, mitre="T1059",
                        )
                        break

        # Brute force detection
        for src_ip, attempts in failed_logons.items():
            if len(attempts) >= BRUTE_FORCE_THRESHOLD:
                self._add_finding(
                    "credential_access", "high",
                    f"Possible brute-force from {src_ip}",
                    f"{len(attempts)} failed logon attempts (Event 4625) from {src_ip}",
                    key, {"source": src_ip, "attempt_count": len(attempts),
                          "samples": attempts[:5]},
                    score=65, mitre="T1110",  # Brute Force
                )

        # Store event distribution
        self.stats[f"{key}_event_distribution"] = dict(event_id_counts.most_common(20))

    # ── Execution evidence ──

    def _detect_execution(self, key: str, rows: list[dict]):
        for idx, entry in enumerate(rows):
            name = self._get(entry, ["Name", "name", "Executable", "executable", "FileName"])
            path = self._get(entry, ["Path", "path", "FullPath"])

            evidence = {"row_index": idx, "name": name, "path": path}

            full = f"{name} {path}"
            for pattern, desc, sev in self._check_suspicious_paths(full, proc_name=name):
                self._add_finding(
                    "execution", "medium",
                    f"Execution evidence from suspicious path",
                    f"'{name}' executed from {desc}: {path}",
                    key, evidence,
                    score=45, mitre="T1204",
                )

    # ── Registry persistence ──

    # Registry keys that actually provide autorun/persistence
    AUTORUN_KEY_MARKERS = (
        "\\run", "\\runonce", "\\runservices", "\\winlogon",
        "\\explorer\\shell", "\\policies\\explorer\\run",
        "\\currentversion\\run", "userinit", "\\image file execution",
        "\\appinit_dlls", "\\shellserviceobjectdelayload",
    )

    def _detect_persistence_registry(self, key: str, rows: list[dict]):
        for idx, entry in enumerate(rows):
            reg_key = self._get(entry, ["key", "Key", "FullPath", "path"])
            value = self._get(entry, ["value", "Value", "Data"])
            name = self._get(entry, ["name", "Name", "ValueName"])

            evidence = {"row_index": idx, "key": reg_key, "name": name, "value": str(value)[:200]}
            reg_key_l = str(reg_key).lower()
            value_str = str(value)

            # Only inspect the VALUE for suspicious commands (not the value
            # NAME — matching substrings in names like 'acpiex' caused FPs).
            # Require a non-trivial value to avoid empty-string matches.
            if value_str and len(value_str) >= 6:
                for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                    m = re.search(pattern, value_str, re.IGNORECASE)
                    if m and len(m.group(0)) >= 4:
                        # Higher severity if it's actually in an autorun key
                        is_autorun = any(mk in reg_key_l for mk in self.AUTORUN_KEY_MARKERS)
                        self._add_finding(
                            "persistence",
                            sev if (sev in ("critical", "high") and is_autorun) else "medium",
                            f"Suspicious registry value: {desc}",
                            f"Registry value '{name}' in {reg_key} contains {desc}: {value_str[:150]}",
                            key, evidence,
                            score=70 if is_autorun else 45, mitre="T1547.001",
                        )
                        break

            # Autorun pointing to a suspicious path — only flag in real autorun keys
            if value_str and any(mk in reg_key_l for mk in self.AUTORUN_KEY_MARKERS):
                autorun_bin_name = value_str.split("\\")[-1].split(" ")[0]
                for pattern, desc, sev in self._check_suspicious_paths(value_str, proc_name=autorun_bin_name):
                    if sev in ("critical", "high", "medium"):
                        self._add_finding(
                            "persistence", "medium",
                            "Registry autorun from suspicious path",
                            f"Autorun value '{name}' points to {desc}: {value_str[:150]}",
                            key, evidence,
                            score=55, mitre="T1547.001",
                        )
                        break

    # ── LNK file analysis ──

    def _detect_lnk(self, key: str, rows: list[dict]):
        for idx, entry in enumerate(rows):
            target = self._get(entry, ["target", "Target", "TargetPath", "RelativePath", "LocalPath"])
            args = self._get(entry, ["args", "Arguments", "CommandLineArguments"])

            evidence = {"row_index": idx, "target": target, "args": args[:200]}

            full = f"{target} {args}"
            for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                if re.search(pattern, full, re.IGNORECASE):
                    self._add_finding(
                        "execution", sev,
                        f"Suspicious LNK target: {desc}",
                        f"LNK file points to command with {desc}: {full[:200]}",
                        key, evidence,
                        score=70, mitre="T1547.009",
                    )

    # ── File anomaly detection (for large file metadata) ──

    def _detect_file_anomalies(self, key: str, rows: list[dict]):
        """Scan file metadata for suspicious files. Handles huge row counts."""
        suspicious_extensions = re.compile(
            r"\.(exe|dll|scr|bat|cmd|ps1|vbs|js|jse|wsf|hta|jar|msi|com|pif|cpl)$",
            re.IGNORECASE
        )
        double_ext = re.compile(
            r"\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.(exe|scr|bat|cmd|ps1|vbs|com|pif)$",
            re.IGNORECASE
        )

        suspicious_path_count = 0
        double_ext_files = []

        for idx, entry in enumerate(rows):
            path = self._get(entry, ["FullPath", "path", "Path", "OSPath", "_Source", "Name"])
            if not path:
                continue

            # Double extension (masquerading)
            if double_ext.search(path):
                double_ext_files.append({"row_index": idx, "path": path})
                if len(double_ext_files) <= 50:  # Cap evidence
                    self._add_finding(
                        "defense_evasion", "high",
                        "Double extension file (masquerading)",
                        f"File with deceptive double extension: {path}",
                        key, {"row_index": idx, "path": path},
                        score=70, mitre="T1036.007",
                    )

            # Executable in suspicious location
            if suspicious_extensions.search(path):
                file_bin_name = str(path).split("\\")[-1]
                for pattern, desc, sev in self._check_suspicious_paths(path, proc_name=file_bin_name):
                    suspicious_path_count += 1
                    if suspicious_path_count <= 100:  # Cap individual findings
                        self._add_finding(
                            "suspicious_file", "medium",
                            f"Executable in suspicious location",
                            f"Executable file in {desc}: {path}",
                            key, {"row_index": idx, "path": path},
                            score=45, mitre="T1036",
                        )
                    break

        # Summary finding if many suspicious files
        if suspicious_path_count > 100:
            self._add_finding(
                "suspicious_file", "high",
                f"{suspicious_path_count} executables in suspicious locations",
                f"Detected {suspicious_path_count} executable files in temp/appdata/public "
                f"directories across the filesystem — review for malware staging",
                key, {"total_count": suspicious_path_count},
                score=60, mitre="T1036",
            )

        self.stats[f"{key}_suspicious_files"] = suspicious_path_count
        self.stats[f"{key}_double_ext_files"] = len(double_ext_files)

    # ── Generic detection for unknown artifact types ──

    def _detect_generic(self, key: str, rows: list[dict]):
        """Scan any artifact for suspicious command-line patterns.

        IR completeness: scans EVERY row, no cap. Caps only the number of
        emitted findings per artifact to avoid flooding the report with
        thousands of identical hits, but every row is examined.
        """
        emitted = 0
        max_findings = 200
        for idx, entry in enumerate(rows):
            entry_str = str(entry)
            for pattern, desc, sev in SUSPICIOUS_CMDLINE:
                if sev in ("critical", "high") and re.search(pattern, entry_str, re.IGNORECASE):
                    if emitted < max_findings:
                        self._add_finding(
                            "anomaly", sev,
                            f"Suspicious pattern in {key}: {desc}",
                            f"Row {idx} in {key} contains {desc}",
                            key, {"row_index": idx, "data": entry_str[:300]},
                            score=60,
                        )
                        emitted += 1
                    break
        if emitted >= max_findings:
            logger.info(f"Generic scan of {key}: capped at {max_findings} findings "
                        f"(all {len(rows)} rows scanned)")

    # ── Behavioral correlation ──

    def _correlate_behavior(self) -> dict:
        """Correlate findings across artifacts to identify attack patterns."""
        categories = Counter(f["category"] for f in self.findings)
        mitre_tactics = Counter(f["mitre"] for f in self.findings if f["mitre"])

        # Attack chain detection
        chains = []
        cats_present = set(categories.keys())

        if "execution" in cats_present and "persistence" in cats_present:
            chains.append("Execution + Persistence — attacker established a foothold and ensured survival")
        if "credential_access" in cats_present and "privilege_escalation" in cats_present:
            chains.append("Credential Access + Privilege Escalation — account compromise and elevation")
        if "credential_access" in cats_present and "lateral_movement" in cats_present:
            chains.append("Credential Access + Lateral Movement — attacker harvesting creds to spread")
        if "defense_evasion" in cats_present:
            chains.append("Defense Evasion detected — attacker actively covering tracks")
        if "network_anomaly" in cats_present and "execution" in cats_present:
            chains.append("Execution + Network anomaly — possible C2 communication channel")
        if "lateral_movement" in cats_present:
            chains.append("Lateral Movement detected — attacker moving between hosts")
        if "exfiltration" in cats_present:
            chains.append("Data staging/exfiltration indicators — potential data theft")

        # Full kill chain
        kill_chain_stages = {"execution", "persistence", "privilege_escalation",
                             "defense_evasion", "credential_access", "lateral_movement"}
        present_stages = kill_chain_stages & cats_present
        if len(present_stages) >= 4:
            chains.insert(0, f"FULL ATTACK CHAIN — {len(present_stages)} kill-chain stages present: "
                         f"{', '.join(sorted(present_stages))}. Strong indication of a coordinated intrusion.")

        # Ransomware pattern
        has_shadow_delete = any("shadow" in f["title"].lower() or "ransomware" in f["title"].lower()
                                for f in self.findings)
        has_mass_files = any("executables in suspicious" in f["title"].lower()
                            for f in self.findings)
        if has_shadow_delete:
            chains.append("RANSOMWARE INDICATORS — shadow copy deletion / encryption artifacts detected")

        return {
            "findings_by_category": dict(categories),
            "mitre_techniques_seen": dict(mitre_tactics.most_common(15)),
            "attack_chains": chains,
            "lolbin_usage_count": len(self.evidence_index.get("lolbins", [])),
        }

    # ── Helper ──

    @staticmethod
    def _get(d: dict, keys: list[str], default: str = "") -> str:
        """Get first matching key from dict (case variations)."""
        if not isinstance(d, dict):
            return default
        for k in keys:
            if k in d and d[k] is not None:
                return str(d[k])
        return default


def build_llm_context(detection_result: dict, max_findings: int = 200) -> str:
    """
    Build a comprehensive but token-efficient context for the LLM
    from detection findings. Includes ALL high/critical findings plus
    representative samples of lower-severity ones.
    """
    lines = []
    lines.append("=== AUTOMATED FORENSIC DETECTION RESULTS ===")
    lines.append(f"Total findings: {detection_result['total_findings']}")
    lines.append(f"Critical: {detection_result['critical_count']}, "
                f"High: {detection_result['high_count']}, "
                f"Medium: {detection_result['medium_count']}")
    lines.append("")

    # Behavioral summary
    behavioral = detection_result.get("behavioral_summary", {})
    if behavioral.get("attack_chains"):
        lines.append("=== ATTACK CHAINS DETECTED ===")
        for chain in behavioral["attack_chains"]:
            lines.append(f"  • {chain}")
        lines.append("")

    if behavioral.get("findings_by_category"):
        lines.append("=== FINDINGS BY CATEGORY ===")
        for cat, count in sorted(behavioral["findings_by_category"].items(),
                                  key=lambda x: -x[1]):
            lines.append(f"  {cat}: {count}")
        lines.append("")

    # Correlation summary
    corr_bits = []
    if behavioral.get("timeline_clusters"):
        corr_bits.append(f"{behavioral['timeline_clusters']} timeline activity bursts")
    if behavioral.get("suspicious_process_chains"):
        corr_bits.append(f"{behavioral['suspicious_process_chains']} suspicious process chains")
    if behavioral.get("frequency_outliers"):
        corr_bits.append(f"{behavioral['frequency_outliers']} rare/outlier artifacts")
    if corr_bits:
        lines.append("=== CROSS-DATASET CORRELATION ===")
        for bit in corr_bits:
            lines.append(f"  • {bit}")
        lines.append("")

    # All findings, prioritized (critical/high first via pre-sort)
    lines.append("=== DETAILED FINDINGS (with evidence pointers) ===")
    for finding in detection_result["findings"][:max_findings]:
        occ = finding.get("occurrences", 1)
        occ_str = f" | seen {occ}× (deduplicated)" if occ > 1 else ""
        lines.append(
            f"\n[{finding['id']}] {finding['severity'].upper()} | "
            f"{finding['category']} | MITRE: {finding['mitre'] or 'N/A'}{occ_str}"
        )
        lines.append(f"  Title: {finding['title']}")
        lines.append(f"  Detail: {finding['description']}")
        locator = finding["evidence"].get("locator") or f"{finding['artifact']} (row {finding['evidence'].get('row_index', 'N/A')})"
        lines.append(f"  Evidence location: {locator}")
        # Include key evidence fields
        ev = finding["evidence"]
        ev_parts = []
        for k in ["name", "path", "cmdline", "command", "remote", "key", "value", "timestamp"]:
            if k in ev and ev[k]:
                ev_parts.append(f"{k}={str(ev[k])[:150]}")
        if ev_parts:
            lines.append(f"  Evidence: {' | '.join(ev_parts)}")

    if detection_result["total_findings"] > max_findings:
        lines.append(f"\n... and {detection_result['total_findings'] - max_findings} more findings "
                    f"(lower severity, omitted for brevity)")

    # Statistics
    lines.append("\n=== COLLECTION STATISTICS ===")
    for key, val in detection_result.get("statistics", {}).items():
        if key.endswith("_total_rows"):
            lines.append(f"  {key.replace('_total_rows', '')}: {val} rows analyzed")

    return "\n".join(lines)