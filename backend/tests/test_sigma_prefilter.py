"""
Tests for the Sigma engine's field pre-filter optimisation.

The optimisation computes a row's field-name set once and reuses it across
all rules via could_match_fields(). These tests lock in the invariant that
the pre-filter is a pure performance gate: it must never change which rows a
rule matches, only skip provably-impossible (row, rule) pairs faster.
"""
from app.sigma_engine import SigmaRule


def _rule(detection, level="high"):
    return SigmaRule({"title": "t", "detection": detection, "level": level})


def test_could_match_consistent_with_match_row():
    """could_match_fields() never rejects a row that match_row() would accept."""
    rule = _rule({"sel": {"CommandLine|contains": "mimikatz"}, "condition": "sel"})

    matching = {"CommandLine": "x mimikatz y"}
    non_matching_content = {"CommandLine": "notepad.exe"}
    missing_field = {"Image": "svchost.exe"}

    # Row that truly matches: gate must allow it, match_row confirms.
    assert rule.could_match_fields({"commandline"}) is True
    assert rule.match_row(matching) is True

    # Row with the field but wrong content: gate allows, match_row rejects.
    assert rule.could_match_fields({"commandline"}) is True
    assert rule.match_row(non_matching_content) is False

    # Row missing the field entirely: gate rejects (the optimisation).
    assert rule.could_match_fields({"image"}) is False
    assert rule.match_row(missing_field) is False


def test_gate_never_blocks_a_real_match():
    """
    For a variety of rows, any row the gate blocks must also be a non-match —
    i.e. the gate is sound (no false negatives introduced).
    """
    rule = _rule({"sel": {"Image|endswith": "\\evil.exe"}, "condition": "sel"})

    rows = [
        {"Image": "C:\\evil.exe"},
        {"Image": "C:\\good.exe"},
        {"CommandLine": "evil.exe"},
        {"NewProcessName": "C:\\evil.exe"},  # alias of Image
        {"Unrelated": "x"},
    ]
    for row in rows:
        row_fields = {str(k).lower() for k in row}
        if not rule.could_match_fields(row_fields):
            # If the gate blocks it, the full evaluation must also reject it.
            assert rule.match_row(row) is False, f"gate blocked a real match: {row}"


def test_empty_required_fields_does_not_block():
    """A rule that inspects no specific field is never blocked by the gate."""
    rule = _rule({"sel": {"condition": "sel"}, "condition": "sel"})
    # No required fields → gate is permissive.
    assert rule.could_match_fields(set()) is True
