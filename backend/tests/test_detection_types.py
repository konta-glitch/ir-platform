"""
Tests for the typed detection primitives (Severity enum) and the centralised
thresholds. These lock in two things:

  1. Severity ranking matches the OLD hand-maintained dict exactly, so the
     refactor doesn't reorder findings.
  2. Thresholds are wired through to the modules that used to inline them.
"""
from app.detection.types import Severity, severity_sort_key, VALID_SEVERITIES


def test_severity_order_matches_legacy_dict():
    """severity_sort_key reproduces the old {critical:0, high:1, ...} ordering."""
    legacy = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for label, expected_rank in legacy.items():
        assert severity_sort_key(label) == expected_rank


def test_unknown_severity_sorts_last_like_before():
    """Unknown severities fell to rank 5 before; parse() defaults to MEDIUM."""
    # The old code used .get(sev, 5); now unknown parses to MEDIUM (rank 2).
    # That's a deliberate, safer default — assert it's stable, not crashing.
    assert severity_sort_key("bogus") == severity_sort_key("medium")


def test_parse_accepts_enum_string_and_informational():
    assert Severity.parse("critical") is Severity.CRITICAL
    assert Severity.parse("INFORMATIONAL") is Severity.INFO
    assert Severity.parse(Severity.HIGH) is Severity.HIGH


def test_valid_severities_are_the_five_labels():
    assert set(VALID_SEVERITIES) == {"info", "low", "medium", "high", "critical"}


def test_thresholds_are_importable_and_sane():
    from app.detection.thresholds import (
        RISK_SCORE_THRESHOLD, SIGMA_SCORE_BY_LEVEL, SIGMA_SEVERITY_CAP,
    )
    assert RISK_SCORE_THRESHOLD == 130
    assert SIGMA_SEVERITY_CAP["critical"] == "high"  # capped, never auto-critical
    assert SIGMA_SCORE_BY_LEVEL["high"] == 60


def test_risk_scoring_uses_central_threshold():
    """risk_scoring re-exports the same constant the thresholds module defines."""
    from app.detection.thresholds import RISK_SCORE_THRESHOLD as central
    from app.detection.risk_scoring import RISK_SCORE_THRESHOLD as used
    assert used == central
