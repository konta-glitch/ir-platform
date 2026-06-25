"""
Tests for the parallelised narrative pass.

The narrative batches now run concurrently. These tests lock in the two
invariants that matter for an IR tool:

  1. ORDER PRESERVED — batches must appear in narrative sequence regardless of
     which finishes first (a later batch that returns sooner must not jump
     ahead in the merged narrative).
  2. NOTHING DROPPED — every batch's findings are represented; concurrency
     doesn't lose results.

The LLM call is mocked with an artificial out-of-order delay so the test
actually exercises the "finishes out of order" path.
"""
import asyncio

import pytest

from app.local_analyzer import LocalAnalyzer


@pytest.fixture
def analyzer():
    # Construct without touching real settings/LLM — we patch the batch call.
    return LocalAnalyzer.__new__(LocalAnalyzer)


def _findings(n):
    return [{"id": f"F{i:04d}", "severity": "high", "title": f"t{i}",
             "category": "c", "description": "d", "artifact": "a",
             "evidence": {}, "score": 50, "mitre": ""} for i in range(n)]


@pytest.mark.asyncio
async def test_batches_stay_in_order_despite_out_of_order_completion(analyzer, monkeypatch):
    """Later batches that resolve first must not reorder the narrative."""

    async def fake_batch(findings, attack_chains, context,
                         batch_num=1, total_batches=1, clusters=None):
        # Make EARLIER batches slower so they finish LAST — worst case for order.
        await asyncio.sleep(0.02 * (total_batches - batch_num + 1))
        return {"attack_narrative": f"narrative-{batch_num}",
                "key_findings": [{"id": findings[0]["id"]}],
                "confidence": 50}

    monkeypatch.setattr(analyzer, "_generate_narrative_batch", fake_batch)

    # Force small batches and real concurrency via settings.
    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("NARRATIVE_BATCH_SIZE", "1")
    monkeypatch.setenv("NARRATIVE_CONCURRENCY", "5")

    result = await analyzer.generate_narrative(_findings(5), attack_chains=[])

    # Merged narrative must list batches 1..5 in order.
    narrative = result["attack_narrative"]
    positions = [narrative.index(f"narrative-{i}") for i in range(1, 6)]
    assert positions == sorted(positions), "batches out of order in narrative"


@pytest.mark.asyncio
async def test_all_findings_represented(analyzer, monkeypatch):
    """Every batch contributes a key finding — nothing dropped."""

    async def fake_batch(findings, attack_chains, context,
                         batch_num=1, total_batches=1, clusters=None):
        return {"attack_narrative": f"n{batch_num}",
                "key_findings": [{"id": f["id"]} for f in findings],
                "confidence": 50}

    monkeypatch.setattr(analyzer, "_generate_narrative_batch", fake_batch)
    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.setenv("NARRATIVE_BATCH_SIZE", "2")
    monkeypatch.setenv("NARRATIVE_CONCURRENCY", "3")

    findings = _findings(7)
    result = await analyzer.generate_narrative(findings, attack_chains=[])

    returned_ids = {kf["id"] for kf in result["key_findings"]}
    assert returned_ids == {f["id"] for f in findings}


@pytest.mark.asyncio
async def test_severity_scope_defaults_to_all(analyzer, monkeypatch):
    """Default narrative scope keeps every severity (IR: nothing dropped)."""
    seen = []

    async def fake_batch(findings, attack_chains, context,
                         batch_num=1, total_batches=1, clusters=None):
        seen.extend(f["id"] for f in findings)
        return {"attack_narrative": "n", "key_findings": [], "confidence": 50}

    monkeypatch.setattr(analyzer, "_generate_narrative_batch", fake_batch)
    from app.config import get_settings
    get_settings.cache_clear()
    monkeypatch.delenv("NARRATIVE_SEVERITIES", raising=False)
    monkeypatch.setenv("NARRATIVE_BATCH_SIZE", "10")

    mixed = (
        [{"id": "C1", "severity": "critical"}]
        + [{"id": "L1", "severity": "low"}]
        + [{"id": "I1", "severity": "info"}]
    )
    # pad to dict shape
    for f in mixed:
        f.update({"title": "t", "category": "c", "description": "d",
                  "artifact": "a", "evidence": {}, "score": 1, "mitre": ""})

    await analyzer.generate_narrative(mixed, attack_chains=[])
    # All three severities reached the narrative pass.
    assert set(seen) == {"C1", "L1", "I1"}
