"""
detection/persistence.py — registry persistence (Run keys, autorun) and
LNK shortcut analysis.
"""

from __future__ import annotations
import re

from app.detection.base import SUSPICIOUS_CMDLINE

# Registry keys that actually provide autorun/persistence
AUTORUN_KEY_MARKERS = (
    "\\run", "\\runonce", "\\runservices", "\\winlogon",
    "\\explorer\\shell", "\\policies\\explorer\\run",
    "\\currentversion\\run", "userinit", "\\image file execution",
    "\\appinit_dlls", "\\shellserviceobjectdelayload",
)


def detect_persistence_registry(engine, key: str, rows: list[dict]) -> None:
    for idx, entry in enumerate(rows):
        reg_key = engine._get(entry, ["key", "Key", "FullPath", "path"])
        value = engine._get(entry, ["value", "Value", "Data"])
        name = engine._get(entry, ["name", "Name", "ValueName"])

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
                    is_autorun = any(mk in reg_key_l for mk in AUTORUN_KEY_MARKERS)
                    engine._add_finding(
                        "persistence",
                        sev if (sev in ("critical", "high") and is_autorun) else "medium",
                        f"Suspicious registry value: {desc}",
                        f"Registry value '{name}' in {reg_key} contains {desc}: {value_str[:150]}",
                        key, evidence,
                        score=70 if is_autorun else 45, mitre="T1547.001",
                    )
                    break

        # Autorun pointing to a suspicious path — only flag in real autorun keys
        if value_str and any(mk in reg_key_l for mk in AUTORUN_KEY_MARKERS):
            autorun_bin_name = value_str.split("\\")[-1].split(" ")[0]
            for pattern, desc, sev in engine._check_suspicious_paths(value_str, proc_name=autorun_bin_name):
                if sev in ("critical", "high", "medium"):
                    engine._add_finding(
                        "persistence", "medium",
                        "Registry autorun from suspicious path",
                        f"Autorun value '{name}' points to {desc}: {value_str[:150]}",
                        key, evidence,
                        score=55, mitre="T1547.001",
                    )
                    break


def detect_lnk(engine, key: str, rows: list[dict]) -> None:
    for idx, entry in enumerate(rows):
        target = engine._get(entry, ["target", "Target", "TargetPath", "RelativePath", "LocalPath"])
        args = engine._get(entry, ["args", "Arguments", "CommandLineArguments"])

        evidence = {"row_index": idx, "target": target, "args": args[:200]}

        full = f"{target} {args}"
        for pattern, desc, sev in SUSPICIOUS_CMDLINE:
            if re.search(pattern, full, re.IGNORECASE):
                engine._add_finding(
                    "execution", sev,
                    f"Suspicious LNK target: {desc}",
                    f"LNK file points to command with {desc}: {full[:200]}",
                    key, evidence,
                    score=70, mitre="T1547.009",
                )
