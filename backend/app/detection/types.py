"""
detection/types.py — shared typed primitives for the detection engine.

Historically findings were plain dicts with string severities ("critical",
"high", ...) compared by accidental alphabetical order, and severity/score
constants were scattered across modules. This module centralises:

  - Severity: an ordered enum so ranking is explicit, not alphabetical luck.
  - SEVERITY_ORDER / normalisation helpers used by sorting and aggregation.

Findings remain dict-shaped on the wire (the rest of the pipeline, the API,
and the report generator all read dicts), so this module does NOT force a
dataclass through the whole codebase. It gives the engine one authoritative
definition of "what a severity is and how they rank", which is where the real
bugs lived.
"""
from __future__ import annotations

from enum import IntEnum


class Severity(IntEnum):
    """
    Ordered severity. Higher value = more severe, so sorting is explicit.

    Note the ordering is intentionally the reverse of the old dict that mapped
    critical->0: there, smaller meant more severe (sort ascending). Here larger
    means more severe; callers sort descending. `sort_key()` below hides this
    so call sites don't have to care.
    """
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value) -> "Severity":
        """
        Coerce a string/enum to Severity. Unknown values fall back to MEDIUM
        (matching the old code's defensive default) rather than raising, so a
        stray severity from a rule file can't crash analysis.
        """
        if isinstance(value, Severity):
            return value
        if isinstance(value, str):
            key = value.strip().upper()
            # Accept the historical "informational" spelling too.
            if key == "INFORMATIONAL":
                return cls.INFO
            member = cls.__members__.get(key)
            if member is not None:
                return member
        return cls.MEDIUM


# Valid severity labels, for validation / iteration.
VALID_SEVERITIES = tuple(s.label for s in Severity)


def severity_sort_key(severity) -> int:
    """
    Sort key for findings: most-severe first when used with the engine's
    existing `(sev, -score)` ascending sort. Returns 0 for CRITICAL ... 4 for
    INFO, preserving the previous sort semantics exactly while routing the
    ordering through the enum instead of a hand-maintained dict.
    """
    return Severity.CRITICAL - Severity.parse(severity)
