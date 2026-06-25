"""
detection/base.py — DetectionEngine core + shared signatures.

This module holds everything detector modules need to share:
  - DetectionEngine class: state (findings/stats), dispatch loop, the
    primitives every detector calls (_add_finding, _get,
    _check_suspicious_paths), and post-processing (dedup, correlation,
    coverage reporting).
  - Shared signature lists (SUSPICIOUS_CMDLINE, SUSPICIOUS_PATHS, LOLBINS,
    WINDOWS_ROOT_ALLOWLIST) — used by multiple detector modules, so they
    live here rather than being owned by any single one.

Detector modules (processes.py, network.py, eventlogs.py, defender.py,
persistence.py, execution_evidence.py, file_anomalies.py) each export a
`detect_*(engine, key, rows)` function and register it against the artifact
keywords it handles via ROUTES. base.py's analyze() dispatch loop is
deliberately routing-table-driven (not a long if/elif chain) specifically
so adding a new detector module never requires editing this file — see
ROUTES below and detection/__init__.py for how a new module wires in.
"""

from __future__ import annotations
import re
import logging
from collections import defaultdict, Counter
from datetime import datetime
from typing import Any, Callable

logger = logging.getLogger(__name__)

# Bump this whenever detection/sigma/correlation logic changes materially.
# It's stamped into every analysis so a report makes clear which engine
# produced it — and stale incidents (analyzed by an older build, then
# re-viewed) are obvious instead of looking like a current result.
ENGINE_VERSION = "2026.06.19-modular-detection"


# ══════════════════════════════════════════════════
# Shared signatures — used across multiple detector modules
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

# Suspicious command-line patterns (regex) — used by processes.py and
# eventlogs.py (4104/4688 script-block/process-creation checks).
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

# Suspicious file paths (process running from these = suspicious) — used by
# processes.py, persistence.py, execution_evidence.py, file_anomalies.py.
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
WINDOWS_ROOT_ALLOWLIST = {
    "explorer.exe", "notepad.exe", "regedit.exe", "write.exe",
    "hh.exe", "winhlp32.exe", "splwow64.exe", "bfsvc.exe",
    "twunk_16.exe", "twunk_32.exe", "ssvagent.exe",
}


# ══════════════════════════════════════════════════
# Routing registry
# ══════════════════════════════════════════════════
#
# Each entry: (keywords, detector_fn). The dispatch loop in analyze() picks
# the FIRST entry whose keywords match the artifact key (substring match,
# case-insensitive) and calls detector_fn(engine, key, rows).
#
# Order matters: more specific matches must come before broader ones (e.g.
# "shimcache" before the generic "prefetch|amcache" execution-evidence
# bucket). See detection/__init__.py for how modules register here.
ROUTES: list[tuple[list[str], Callable]] = []


def register_route(keywords: list[str], detector_fn: Callable) -> None:
    """Register a detector function against a list of artifact-key substrings."""
    ROUTES.append((keywords, detector_fn))


def register_additional_pass(keywords: list[str], detector_fn: Callable) -> None:
    """
    Register a detector that runs as an ADDITIONAL pass alongside whichever
    primary route already matched these keywords — e.g. auth-pattern
    analysis runs alongside the primary eventlog detector, not instead of
    it. Stored separately from ROUTES so the dispatch loop knows to call
    both rather than treating this as a competing first-match route.
    """
    ADDITIONAL_PASSES.append((keywords, detector_fn))


ADDITIONAL_PASSES: list[tuple[list[str], Callable]] = []


# ══════════════════════════════════════════════════
# DetectionEngine core
# ══════════════════════════════════════════════════

class DetectionEngine:
    """Runs comprehensive forensic detection across all collected artifacts."""

    def __init__(self):
        self.findings: list[dict] = []
        self.stats: dict = defaultdict(int)
        self.evidence_index: dict[str, list] = defaultdict(list)

    # ── Shared primitives every detector module uses ──

    @staticmethod
    def _get(d: dict, keys: list[str], default: str = "") -> str:
        for k in keys:
            if k in d and d[k] not in (None, ""):
                return str(d[k])
        return default

    @staticmethod
    def _check_suspicious_paths(path: str, proc_name: str = ""):
        """
        Yield (pattern, desc, sev) for every SUSPICIOUS_PATHS rule that
        matches `path`, EXCEPT the "Executable directly in Windows root"
        rule when `proc_name` is on WINDOWS_ROOT_ALLOWLIST.
        """
        name_lower = proc_name.lower().split("\\")[-1] if proc_name else ""
        for pattern, desc, sev in SUSPICIOUS_PATHS:
            if desc == "Executable directly in Windows root" and name_lower in WINDOWS_ROOT_ALLOWLIST:
                continue
            if re.search(pattern, path, re.IGNORECASE):
                yield pattern, desc, sev

    def _add_finding(self, category: str, severity: str, title: str,
                     description: str, artifact: str, evidence: dict,
                     score: int = 0, mitre: str = ""):
        """Record a finding with evidence pointer. Called by every detector module."""
        # Normalise severity through the Severity enum so an unexpected value
        # (e.g. a typo, or "informational" vs "info") becomes a canonical label
        # instead of silently corrupting sorting and the critical/high counts.
        from app.detection.types import Severity
        severity = Severity.parse(severity).label
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

    # ── Main entry point ──

    def analyze(self, data: dict, progress_cb=None) -> dict:
        """
        Analyze ALL data and return prioritized findings with evidence.

        progress_cb(artifact_name, processed_rows, total_rows) is called
        per artifact so the caller can stream live progress.
        """
        self.findings = []
        self.stats = defaultdict(int)
        self.evidence_index = defaultdict(list)

        artifacts = [(k, v) for k, v in data.items()
                     if not k.startswith("_") and isinstance(v, list)]
        total_all = sum(len(v) for _, v in artifacts) or 1
        processed_all = 0

        for key, rows in artifacts:
            self.stats[f"{key}_total_rows"] = len(rows)
            key_lower = key.lower()

            if progress_cb:
                progress_cb(key, processed_all, total_all)

            matched = False
            for keywords, detector_fn in ROUTES:
                if any(kw in key_lower for kw in keywords):
                    detector_fn(self, key, rows)
                    matched = True
                    break
            if not matched:
                from app.detection.generic import detect_generic
                detect_generic(self, key, rows)

            # Additional passes run regardless of which primary route fired,
            # as long as their own keywords match — e.g. auth-pattern
            # analysis runs whenever an eventlog-shaped artifact was seen.
            for keywords, detector_fn in ADDITIONAL_PASSES:
                if any(kw in key_lower for kw in keywords):
                    detector_fn(self, key, rows)

            processed_all += len(rows)
            if progress_cb:
                progress_cb(key, processed_all, total_all)

        # Process risk aggregation runs BEFORE behavior correlation — the
        # attack-chain narrative built by _correlate_behavior() reads
        # engine.findings and needs to see correlated_risk summary
        # findings (emitted here) to mention them in the narrative.
        from app.detection.risk_scoring import aggregate_process_risk
        aggregate_process_risk(self)

        behavioral = self._correlate_behavior()
        self._enrich_source_files(data)
        self._deduplicate_findings()

        from app.detection.types import severity_sort_key
        self.findings.sort(key=lambda f: (severity_sort_key(f["severity"]), -f.get("score", 0)))

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

    # ── Post-processing ──

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
                        ev["source_file"] = unquote(str(src)).replace("%2F", "/")
            if ev.get("source_file"):
                ev["locator"] = f"{ev['source_file']} (row {row_idx})"
            elif row_idx is not None:
                ev["locator"] = f"{artifact} (row {row_idx})"

    def _correlate_behavior(self) -> dict:
        """Cross-finding correlation — attack chains, category summary."""
        from app.detection.behavior_correlation import correlate_behavior
        return correlate_behavior(self)
