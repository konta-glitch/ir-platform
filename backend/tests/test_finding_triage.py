"""
Tests for per-finding triage.

Triage sits on top of the detection findings (which live in raw_artifacts) as a
separate finding_triage map on the incident, so marking a finding never mutates
detection output and marking one finding leaves the others untouched.
"""
import pytest

from app.models import Incident
from app.orchestrator import Orchestrator


@pytest.fixture
def orch_with_incident():
    o = Orchestrator()
    o.incidents._incidents["inc1"] = Incident(id="inc1", title="Test")
    return o


def test_sets_verdict_and_note(orch_with_incident):
    o = orch_with_incident
    inc = o.triage_finding("inc1", "F1", verdict="true_positive", note="confirmed")
    entry = inc.finding_triage["F1"]
    assert entry["verdict"] == "true_positive"
    assert entry["note"] == "confirmed"
    assert "updated_at" in entry


def test_note_update_preserves_verdict(orch_with_incident):
    o = orch_with_incident
    o.triage_finding("inc1", "F1", verdict="false_positive")
    inc = o.triage_finding("inc1", "F1", note="just a note")
    assert inc.finding_triage["F1"]["verdict"] == "false_positive"
    assert inc.finding_triage["F1"]["note"] == "just a note"


def test_other_findings_untouched(orch_with_incident):
    o = orch_with_incident
    o.triage_finding("inc1", "F1", verdict="true_positive")
    inc = o.triage_finding("inc1", "F2", verdict="benign")
    assert inc.finding_triage["F1"]["verdict"] == "true_positive"
    assert inc.finding_triage["F2"]["verdict"] == "benign"


def test_clear_removes_entry(orch_with_incident):
    o = orch_with_incident
    o.triage_finding("inc1", "F1", verdict="needs_review")
    inc = o.triage_finding("inc1", "F1", verdict="clear")
    assert "F1" not in inc.finding_triage


def test_triage_does_not_touch_detection_findings(orch_with_incident):
    """Marking a finding must not mutate the detection output."""
    o = orch_with_incident
    inc = o.incidents._incidents["inc1"]
    inc.raw_artifacts["detection_findings"] = [{"id": "F1", "title": "x"}]
    o.triage_finding("inc1", "F1", verdict="false_positive")
    # Detection finding is unchanged; triage lives separately.
    assert inc.raw_artifacts["detection_findings"] == [{"id": "F1", "title": "x"}]
    assert inc.finding_triage["F1"]["verdict"] == "false_positive"


def test_unknown_incident_returns_none(orch_with_incident):
    assert orch_with_incident.triage_finding("nope", "F1", verdict="benign") is None
