"""
Extended detection rules — Shimcache, UserAssist, Shellbags.

These three artifacts are already parsed by image_analyzer.py but previously
fell through to `_detect_generic()`, which only does light frequency analysis.
This module gives each one a dedicated detector with the specific forensic
signal each artifact actually carries:

  - Shimcache (AppCompatCache): proves a binary EXECUTED at some point, even
    if the file itself has since been deleted. Attackers who clean up their
    payload often forget this survives. High value for "did X run?" questions.

  - UserAssist: proves a program was launched via GUI (double-click / Start
    menu), with a run count and last-execution timestamp. Complements
    Shimcache for attacks that don't use the command line at all.

  - Shellbags: proves a user (or attacker with an interactive session)
    BROWSED to a folder — including removable drives, network shares, and
    folders that have since been deleted. Useful for staging/exfil paths.

Design: this module is intentionally separate from detection_engine.py's
core class so it can be unit-tested and extended independently. It is wired
in via DetectionEngine._detect_shimcache / _detect_userassist /
_detect_shellbags, which the main analyze() dispatch table routes to.
"""

from __future__ import annotations
import re
import logging
from collections import Counter
from typing import Any

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════
# Signatures
# ══════════════════════════════════════════════════

# Paths that are suspicious regardless of which artifact observed them —
# reused from the same threat model as detection_engine.SUSPICIOUS_PATHS,
# duplicated narrowly here to keep this module import-independent.
SUSPICIOUS_EXEC_PATHS = [
    (r"\\Temp\\", "Executed from Temp", "medium"),
    (r"\\AppData\\Local\\Temp\\", "Executed from user Temp", "medium"),
    (r"\\AppData\\Roaming\\", "Executed from Roaming AppData", "low"),
    (r"\\ProgramData\\", "Executed from ProgramData", "low"),
    (r"\\Users\\Public\\", "Executed from Public", "medium"),
    (r"\\Downloads\\", "Executed from Downloads", "medium"),
    (r"\\Windows\\Temp\\", "Executed from Windows Temp", "medium"),
    (r"\\\$Recycle\.Bin\\", "Executed from Recycle Bin", "high"),
    (r"^[A-Z]:\\[^\\]+\.exe$", "Executed directly from drive root", "medium"),
]

# Double-extension / masquerading patterns — e.g. invoice.pdf.exe
DOUBLE_EXTENSION = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png)\.exe$", re.IGNORECASE
)

# Folders that are suspicious to navigate to interactively (shellbags) —
# distinct from exec paths because the signal here is "an attacker with an
# interactive session browsed here", not "a program ran from here".
SUSPICIOUS_BROWSE_PATHS = [
    (r"\\Temp\\", "Browsed to Temp folder", "low"),
    (r"\\AppData\\", "Browsed to AppData", "low"),
    (r"\\\$Recycle\.Bin\\", "Browsed to Recycle Bin", "medium"),
    (r"^[A-Z]:\\$", "Browsed to removable/external drive root", "medium"),
    (r"\\\\[^\\]+\\[^\\]+", "Browsed to network share (UNC path)", "medium"),
]


def _safe(value: Any) -> str:
    return str(value) if value is not None else ""


# ══════════════════════════════════════════════════
# Detectors — each takes (add_finding_fn, key, rows) and is self-contained
# ══════════════════════════════════════════════════

def detect_shimcache(add_finding, key: str, rows: list[dict]) -> None:
    """
    Shimcache / AppCompatCache: each entry proves a binary executed (or was
    at least present and cached by the compatibility subsystem) at some
    point. The file itself may be long gone — this is often the LAST
    surviving evidence of execution after an attacker deletes their tooling.
    """
    path_counter: Counter = Counter()

    for idx, row in enumerate(rows):
        path = _safe(row.get("path"))
        last_modified = _safe(row.get("last_modified"))
        if not path:
            continue

        path_counter[path.lower()] += 1
        evidence = {"row_index": idx, "path": path, "last_modified": last_modified}

        for pattern, desc, sev in SUSPICIOUS_EXEC_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                add_finding(
                    "execution_evidence", sev,
                    f"Shimcache: {desc}",
                    f"AppCompatCache shows execution evidence for '{path}' "
                    f"(last modified: {last_modified}). The source binary may "
                    f"no longer exist on disk — this cache often survives "
                    f"after the file is deleted.",
                    key, evidence,
                    score=55 if sev == "medium" else 70,
                    mitre="T1218",  # System Binary Proxy Execution (generic LOLBin)
                )

        if DOUBLE_EXTENSION.search(path):
            add_finding(
                "execution_evidence", "high",
                "Shimcache: double-extension masquerade executed",
                f"AppCompatCache shows execution of '{path}', which uses a "
                f"double extension to disguise an executable as a document — "
                f"a common phishing-payload trick.",
                key, evidence,
                score=80, mitre="T1036.007",  # Masquerading: Double File Extension
            )


def detect_userassist(add_finding, key: str, rows: list[dict]) -> None:
    """
    UserAssist: proves GUI-launched execution (Start menu, double-click,
    desktop shortcut) with a run count and last-execution timestamp.
    Complements command-line-based detections — many attacks (trojanized
    installers, malicious shortcuts) never touch a shell at all.
    """
    for idx, row in enumerate(rows):
        path = _safe(row.get("path"))
        run_count = row.get("run_count") or 0
        last_executed = _safe(row.get("last_executed"))
        if not path:
            continue

        evidence = {
            "row_index": idx, "path": path,
            "run_count": run_count, "last_executed": last_executed,
        }

        for pattern, desc, sev in SUSPICIOUS_EXEC_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                add_finding(
                    "execution_evidence", sev,
                    f"UserAssist: {desc} (GUI-launched)",
                    f"UserAssist shows '{path}' was launched via GUI "
                    f"{run_count}x, last on {last_executed}. This indicates "
                    f"interactive (double-click/Start menu) execution, not "
                    f"command-line invocation.",
                    key, evidence,
                    score=50 if sev == "medium" else 65,
                    mitre="T1204.002",  # User Execution: Malicious File
                )

        if DOUBLE_EXTENSION.search(path):
            add_finding(
                "execution_evidence", "high",
                "UserAssist: double-extension masquerade launched by user",
                f"UserAssist shows the user double-clicked '{path}' "
                f"{run_count}x — a double-extension filename suggests the "
                f"user was tricked into running it.",
                key, evidence,
                score=82, mitre="T1204.002",
            )

        # A single-run, very recently executed unusual binary from a normal
        # location is lower signal on its own, but worth surfacing if it's
        # the ONLY execution of that binary ever recorded (run_count == 1)
        # combined with a suspicious path — already covered above. No
        # additional rule needed here; kept as a placeholder for tuning.


def detect_shellbags(add_finding, key: str, rows: list[dict]) -> None:
    """
    Shellbags: proves a user (or an attacker operating interactively)
    browsed to a folder in Explorer — including folders, removable drives,
    or network shares that have since been deleted/disconnected. This is
    pure navigation evidence, distinct from execution evidence.
    """
    for idx, row in enumerate(rows):
        path = _safe(row.get("path"))
        last_accessed = _safe(row.get("last_accessed"))
        if not path:
            continue

        evidence = {"row_index": idx, "path": path, "last_accessed": last_accessed}

        for pattern, desc, sev in SUSPICIOUS_BROWSE_PATHS:
            if re.search(pattern, path, re.IGNORECASE):
                add_finding(
                    "file_access", sev,
                    f"Shellbags: {desc}",
                    f"Shellbags show Explorer navigation to '{path}' "
                    f"(last accessed: {last_accessed}). This proves "
                    f"interactive browsing even if the folder/drive/share no "
                    f"longer exists or is disconnected.",
                    key, evidence,
                    score=45 if sev == "low" else 60,
                    mitre="T1083",  # File and Directory Discovery
                )
