"""
Tests for regenerating the narrative with the latest triage + enrichment.

IR is iterative: the first narrative is written before cloud enrichment answers
the knowledge gaps and before the analyst triages anything. Regeneration re-runs
the narrative pass from the stored findings, optionally dropping false positives
and feeding Claude's enrichment answers into the context — without mutating the
detection findings themselves.
"""
import pytest

from app.models import Incident, AnalysisResult
from app.orchestrator import Orchestrator


def _orch(findings, triage=None, enrichments=None):
    o = Orchestrator()
    inc = Incident(id="i1", title="T")
    inc.raw_artifacts["detection_findings"] = findings
    inc.finding_triage = triage or {}
    if enrichments:
        inc.analysis = AnalysisResult(summary="s", severity="high")
        inc.analysis.cloud_enrichments = enrichments
    o.incidents._incidents["i1"] = inc
    return o


@pytest.fixture
def findings():
    return [
        {"id": "F1", "severity": "critical", "title": "malware"},
        {"id": "F2", "severity": "low", "title": "noise"},
    ]


@pytest.mark.asyncio
async def test_respect_triage_drops_false_positives(findings):
    o = _orch(findings, triage={"F2": {"verdict": "false_positive"}})
    captured = {}
    async def fake(findings, attack_chains, context=""):
        captured["ids"] = [f["id"] for f in findings]
        return {"attack_narrative": "x"}
    o.local.generate_narrative = fake
    await o.regenerate_narrative("i1", respect_triage=True, include_enrichment=False)
    assert "F2" not in captured["ids"]
    assert "F1" in captured["ids"]


@pytest.mark.asyncio
async def test_no_triage_keeps_all(findings):
    o = _orch(findings, triage={"F2": {"verdict": "false_positive"}})
    captured = {}
    async def fake(findings, attack_chains, context=""):
        captured["ids"] = [f["id"] for f in findings]
        return {"attack_narrative": "x"}
    o.local.generate_narrative = fake
    await o.regenerate_narrative("i1", respect_triage=False, include_enrichment=False)
    assert "F2" in captured["ids"]  # FP kept when triage not respected


@pytest.mark.asyncio
async def test_verdict_annotated_on_kept_findings(findings):
    o = _orch(findings, triage={"F1": {"verdict": "true_positive"}})
    captured = {}
    async def fake(findings, attack_chains, context=""):
        captured["findings"] = findings
        return {"attack_narrative": "x"}
    o.local.generate_narrative = fake
    await o.regenerate_narrative("i1", respect_triage=True, include_enrichment=False)
    f1 = next(f for f in captured["findings"] if f["id"] == "F1")
    assert f1.get("analyst_verdict") == "true_positive"


@pytest.mark.asyncio
async def test_enrichment_prepended_to_context(findings):
    o = _orch(findings, enrichments=["screenconnect is a known RMM abuse"])
    captured = {}
    async def fake(findings, attack_chains, context=""):
        captured["context"] = context
        return {"attack_narrative": "x"}
    o.local.generate_narrative = fake
    await o.regenerate_narrative("i1", respect_triage=False, include_enrichment=True)
    assert "known RMM abuse" in captured["context"]


@pytest.mark.asyncio
async def test_detection_findings_not_mutated(findings):
    o = _orch(findings, triage={"F1": {"verdict": "true_positive"}})
    async def fake(findings, attack_chains, context=""):
        return {"attack_narrative": "x"}
    o.local.generate_narrative = fake
    await o.regenerate_narrative("i1", respect_triage=True, include_enrichment=False)
    stored = o.incidents._incidents["i1"].raw_artifacts["detection_findings"]
    # Stored findings have no analyst_verdict key — only the copy sent to the LLM did.
    assert all("analyst_verdict" not in f for f in stored)


@pytest.mark.asyncio
async def test_unknown_incident_returns_none(findings):
    o = _orch(findings)
    assert await o.regenerate_narrative("nope") is None
