"""
detection/generic.py — fallback detector for artifact types no other
module's ROUTES claimed.

Used by base.py's analyze() dispatch loop when no registered route matches
an artifact key — ensures every artifact gets at least a baseline scan
rather than being silently skipped just because it's an unrecognized
collector output format.
"""

from __future__ import annotations
import re
import logging

from app.detection.base import SUSPICIOUS_CMDLINE

logger = logging.getLogger(__name__)


def detect_generic(engine, key: str, rows: list[dict]) -> None:
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
                    engine._add_finding(
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
