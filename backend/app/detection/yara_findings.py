"""
detection/yara_findings.py — convert YARA scan hits into findings.

The YARA scanner (app/yara_scanner.py) runs during collection and emits a
'yara_matches' artifact: one row per rule that matched a file's content.
This detector turns each of those into a finding, carrying through the
rule's own severity and MITRE mapping.

Why this is high-value: a YARA hit is CONTENT-based evidence — it found a
known-bad pattern inside the actual file bytes, independent of where the
file lives or what its command line looked like. That makes it strong
corroboration: a file that's both in a suspicious location (path heuristic)
AND matches a malware YARA rule (content) is a far stronger signal than
either alone, and the process risk aggregation pass will combine them.

False-positive control: string-based YARA rules (e.g. "contains
-EncodedCommand and Invoke-Expression") legitimately match SECURITY
PRODUCTS and admin tooling, because those products contain the very
strings they're built to DETECT. A real production run flagged
SentinelOne's SentinelUI.exe this way. So string-based rule hits are
suppressed (or heavily downgraded) when the file lives in a known-good
vendor install path. High-specificity byte-pattern rules (Mimikatz,
Cobalt Strike beacon markers) are NEVER suppressed — those byte sequences
don't legitimately appear in vendor binaries.
"""

from __future__ import annotations

# Install paths where vendor/security software legitimately lives. A
# string-based YARA hit here is almost always the product containing
# detection signatures, not malware. Matched case-insensitively as a
# substring of the file path.
KNOWN_GOOD_VENDOR_PATHS = (
    "\\program files\\windows defender",
    "/program files/windows defender",
    "sentinelone", "sentinel agent", "sentinelui",
    "crowdstrike", "\\falcon\\", "/falcon/",
    "carbon black", "carbonblack", "\\cb\\",
    "microsoft\\windows defender", "microsoft/windows defender",
    "\\msmpeng", "windefend",
    "mcafee", "symantec", "sophos", "trend micro", "trendmicro",
    "eset\\", "eset/", "kaspersky", "bitdefender", "malwarebytes",
    "cylance", "cortex xdr", "\\sysinternals\\", "/sysinternals/",
    "\\program files\\git\\", "/program files/git/",
    "\\powershell\\", "/powershell/",
)

# Rules that are HIGH-SPECIFICITY (distinctive byte patterns / tool names
# that don't legitimately appear in vendor software). These are never
# suppressed by the vendor-path allowlist — a Mimikatz byte signature in
# SentinelOne would itself be alarming, not benign.
HIGH_SPECIFICITY_RULES = {
    "SUSP_Mimikatz_Strings",
    "SUSP_CobaltStrike_Beacon_Indicators",
    "SUSP_Ransomware_Note_Indicators",
}


# YARA rule name → (forced_severity, mitre, human_readable_family)
# When a YARA hit matches one of these prefixes/substrings, the severity
# is OVERRIDDEN to the value here regardless of the rule own metadata.
#
# Rationale: many YARA rules ship with conservative severity ("medium") to
# reduce noise in threat hunting. But for an IR tool the stakes are
# different — a HijackLoader stub in slack.exe is CRITICAL, not MEDIUM.
MALWARE_SEVERITY_OVERRIDES: dict = {
    # Loaders / droppers
    "CAPE_Hijackloaderstub":      ("critical", "T1574.002", "HijackLoader stub"),
    "CAPE_Hijackloader":          ("critical", "T1574.002", "HijackLoader"),
    "HijackLoader":               ("critical", "T1574.002", "HijackLoader"),
    # C2 / RAT frameworks
    "SUSP_CobaltStrike":          ("critical", "T1071.001", "Cobalt Strike beacon"),
    "CobaltStrike":               ("critical", "T1071.001", "Cobalt Strike"),
    "CAPE_CobaltStrike":          ("critical", "T1071.001", "Cobalt Strike"),
    "Meterpreter":                ("critical", "T1059.001", "Meterpreter"),
    "CAPE_Meterpreter":           ("critical", "T1059.001", "Meterpreter"),
    "Sliver":                     ("critical", "T1071.001", "Sliver C2"),
    "Brute_Ratel":                ("critical", "T1071.001", "Brute Ratel C4"),
    "CAPE_AsyncRAT":              ("critical", "T1571",     "AsyncRAT"),
    "CAPE_NjRat":                 ("critical", "T1571",     "NjRAT"),
    "CAPE_Quasar":                ("critical", "T1571",     "QuasarRAT"),
    # Credential dumpers
    "SUSP_Mimikatz":              ("critical", "T1003.001", "Mimikatz"),
    "Mimikatz":                   ("critical", "T1003.001", "Mimikatz"),
    "CAPE_Mimikatz":              ("critical", "T1003.001", "Mimikatz"),
    # Ransomware
    "CAPE_LockBit":               ("critical", "T1486",     "LockBit ransomware"),
    "CAPE_Ryuk":                  ("critical", "T1486",     "Ryuk ransomware"),
    "CAPE_Conti":                 ("critical", "T1486",     "Conti ransomware"),
    "CAPE_BlackCat":              ("critical", "T1486",     "BlackCat/ALPHV ransomware"),
    "Ransomware":                 ("critical", "T1486",     "Ransomware"),
    # Obfuscators on non-vendor files
    "COD3NYM_Reactor_Indicators": ("high",     "T1027.002", "Ezriz .NET Reactor obfuscation"),
    "CAPE_DotNetReactor":         ("high",     "T1027.002", ".NET Reactor obfuscation"),
    "CAPE_ConfuserEx":            ("high",     "T1027.002", "ConfuserEx obfuscation"),
    # RMM tools — dual-use, context-dependent
    "DITEKSHEN_INDICATOR_RMM":    ("high",     "T1219",     "Remote monitoring/management tool"),
    "INDICATOR_RMM":              ("high",     "T1219",     "Remote monitoring/management tool"),
    # Web shells
    "Webshell":                   ("critical", "T1505.003", "Web shell"),
    "CAPE_Webshell":              ("critical", "T1505.003", "Web shell"),
    # Rootkits / bootkits
    "Rootkit":                    ("critical", "T1014",     "Rootkit"),
    "Bootkit":                    ("critical", "T1542",     "Bootkit"),
}


def _override_severity(rule: str):
    """Return (severity, mitre, family_name) if rule matches a known-bad family, else None."""
    for prefix, override in MALWARE_SEVERITY_OVERRIDES.items():
        if rule.startswith(prefix) or prefix in rule:
            return override
    return None

def _is_known_good_vendor_path(path: str) -> bool:
    p = str(path).lower()
    return any(marker in p for marker in KNOWN_GOOD_VENDOR_PATHS)


def detect_yara_matches(engine, key: str, rows: list[dict]) -> None:
    for idx, match in enumerate(rows):
        rule = match.get("rule", "unknown_rule")
        severity = match.get("severity", "medium")
        mitre = match.get("mitre", "")
        description = match.get("description", rule)
        filename = match.get("filename", match.get("_source_file", "unknown file"))
        matched_strings = match.get("matched_strings", [])

        # False-positive control for string-based rules hitting legitimate
        # vendor/security software (see module docstring — SentinelOne's
        # SentinelUI.exe matched the PowerShell-encoded-command rule because
        # the product CONTAINS that string to detect it).
        if (rule not in HIGH_SPECIFICITY_RULES
                and _is_known_good_vendor_path(filename)):
            # Don't emit a compromise-implying finding. Downgrade to a
            # low-severity informational note so the signal isn't lost
            # entirely (an analyst may still want to know a vendor binary
            # matched), but it won't drive severity or risk aggregation.
            engine._add_finding(
                "info", "low",
                f"YARA match in known-good vendor file (likely benign): {rule}",
                f"File '{filename}' matched string-based YARA rule '{rule}', but the "
                f"file is in a known security-product/vendor install path. Security "
                f"products legitimately contain these strings because they DETECT the "
                f"technique — this is almost certainly benign and is recorded for "
                f"completeness only, not as a compromise indicator.",
                key,
                {"row_index": idx, "rule": rule, "path": filename,
                 "name": filename.split("/")[-1].split("\\")[-1],
                 "suppressed_reason": "known-good vendor path"},
                score=5, mitre="",
            )
            continue

        # Severity override for known malware families — many YARA rules ship
        # with conservative severity to reduce threat-hunting noise, but an IR
        # tool needs to surface HijackLoader in slack.exe as CRITICAL, not MEDIUM.
        override = _override_severity(rule)
        if override:
            sev_override, mitre_override, family = override
            if severity != sev_override:
                severity = sev_override
                if not mitre:
                    mitre = mitre_override
                description = f"{family} — {description}"

        # Score scales with severity — YARA content hits are high-confidence
        # by nature (a pattern matched actual file bytes), so these score
        # higher than equivalent metadata-only heuristics.
        score = {
            "critical": 95, "high": 80, "medium": 60, "low": 40,
        }.get(severity, 60)

        evidence = {
            "row_index": idx,
            "rule": rule,
            "path": filename,
            "name": filename.split("/")[-1].split("\\")[-1],
            "matched_strings": matched_strings,
        }

        strings_note = ""
        if matched_strings:
            strings_note = f" Matched patterns: {'; '.join(matched_strings[:3])}."

        engine._add_finding(
            "malware_signature", severity,
            f"YARA match: {rule}",
            f"File '{filename}' matched YARA rule '{rule}' ({description}). "
            f"This is content-based detection — a known-bad pattern was found "
            f"inside the file's actual bytes, independent of its location or "
            f"command line.{strings_note}",
            key, evidence,
            score=score, mitre=mitre,
        )
