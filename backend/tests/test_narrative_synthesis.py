"""
Tests for the narrative synthesis pass — the third LLM call that folds the
per-batch narratives into one coherent incident story.

Synthesis is additive: it replaces the concatenated-sections narrative only
when it succeeds, and the merged sections survive as a fallback on any failure
or when disabled.
"""
import pytest

from app.local_analyzer import LocalAnalyzer


def _analyzer_with_llm(reply):
    a = LocalAnalyzer.__new__(LocalAnalyzer)

    async def fake_call(system, user, temperature=0.1, max_tokens=0, timeout=0.0):
        return reply

    a._call_llm = fake_call
    return a


@pytest.mark.asyncio
async def test_synthesis_returns_single_narrative():
    a = _analyzer_with_llm("The attacker installed ScreenConnect [F0297] then "
                           "ran the hijack loader [F0018]. One coherent story.")
    merged = {
        "attack_narrative": "[batch 1]\nslack malware\n\n---\n\n[batch 2]\nscreenconnect",
        "key_findings": [{"finding_id": "F0018", "why_it_matters": "malware"}],
    }
    out = await a._synthesize_narrative(merged, ["chain A"], "ctx")
    assert "coherent story" in out
    assert "[batch 1]" not in out  # sections collapsed into prose


@pytest.mark.asyncio
async def test_synthesis_strips_think_block():
    a = _analyzer_with_llm("<think>let me reason</think>\nThe final narrative.")
    merged = {"attack_narrative": "x", "key_findings": []}
    out = await a._synthesize_narrative(merged, [], "")
    assert out == "The final narrative."


@pytest.mark.asyncio
async def test_synthesis_rejects_json_echo():
    """If the model echoes JSON despite instructions, signal a keep-sections."""
    a = _analyzer_with_llm('{"attack_narrative": "oops json"}')
    merged = {"attack_narrative": "sections", "key_findings": []}
    out = await a._synthesize_narrative(merged, [], "")
    assert out == ""  # caller keeps the merged sections


@pytest.mark.asyncio
async def test_synthesis_empty_input_returns_empty():
    a = _analyzer_with_llm("anything")
    out = await a._synthesize_narrative({"attack_narrative": "  "}, [], "")
    assert out == ""


def test_synthesize_config_default_on():
    from app.config import Settings
    assert Settings().narrative_synthesize is True
