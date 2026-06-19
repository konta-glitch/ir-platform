"""
detection/file_anomalies.py — file metadata anomaly detection.

Handles large generic file listings (SearchGlobs, file metadata dumps) —
the "everything else" file-system view, distinct from execution evidence
(which proves something RAN) or persistence (which proves something
SURVIVES a reboot). This is just "does this file's name/location look
wrong".
"""

from __future__ import annotations
import re
import logging

logger = logging.getLogger(__name__)


def detect_file_anomalies(engine, key: str, rows: list[dict]) -> None:
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
        path = engine._get(entry, ["FullPath", "path", "Path", "OSPath", "_Source", "Name"])
        if not path:
            continue

        # Double extension (masquerading)
        if double_ext.search(path):
            double_ext_files.append({"row_index": idx, "path": path})
            if len(double_ext_files) <= 50:  # Cap evidence
                engine._add_finding(
                    "defense_evasion", "high",
                    "Double extension file (masquerading)",
                    f"File with deceptive double extension: {path}",
                    key, {"row_index": idx, "path": path},
                    score=70, mitre="T1036.007",
                )

        # Executable in suspicious location
        if suspicious_extensions.search(path):
            file_bin_name = str(path).split("\\")[-1]
            for pattern, desc, sev in engine._check_suspicious_paths(path, proc_name=file_bin_name):
                suspicious_path_count += 1
                if suspicious_path_count <= 100:  # Cap individual findings
                    engine._add_finding(
                        "suspicious_file", "medium",
                        f"Executable in suspicious location",
                        f"Executable file in {desc}: {path}",
                        key, {"row_index": idx, "path": path},
                        score=45, mitre="T1036",
                    )
                break

    # Summary finding if many suspicious files
    if suspicious_path_count > 100:
        engine._add_finding(
            "suspicious_file", "high",
            f"{suspicious_path_count} executables in suspicious locations",
            f"Detected {suspicious_path_count} executable files in temp/appdata/public "
            f"directories across the filesystem — review for malware staging",
            key, {"total_count": suspicious_path_count},
            score=60, mitre="T1036",
        )

    engine.stats[f"{key}_suspicious_files"] = suspicious_path_count
    engine.stats[f"{key}_double_ext_files"] = len(double_ext_files)
