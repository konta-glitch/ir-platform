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
"""

from __future__ import annotations


def detect_yara_matches(engine, key: str, rows: list[dict]) -> None:
    for idx, match in enumerate(rows):
        rule = match.get("rule", "unknown_rule")
        severity = match.get("severity", "medium")
        mitre = match.get("mitre", "")
        description = match.get("description", rule)
        filename = match.get("filename", match.get("_source_file", "unknown file"))
        matched_strings = match.get("matched_strings", [])

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
            "name": filename.split("/")[-1],
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
