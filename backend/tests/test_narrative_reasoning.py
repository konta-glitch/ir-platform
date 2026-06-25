"""
Tests for the narrative pass reasoning/timeout controls that keep reasoning
models (DeepSeek-R1) from burning their whole token budget on <think> and
returning empty content.
"""
import inspect

from app.local_analyzer import LocalAnalyzer


def test_call_llm_accepts_timeout():
    """_call_llm forwards a per-call timeout (narrative pass needs a long one)."""
    sig = inspect.signature(LocalAnalyzer._call_llm)
    assert "timeout" in sig.parameters


def test_config_has_narrative_reasoning_controls():
    from app.config import Settings
    s = Settings()
    # No-think on by default (reasoning is wasteful for the formatting task).
    assert s.narrative_disable_thinking is True
    # Generous timeout so slow reasoning models aren't cut off.
    assert s.narrative_timeout >= 300


def test_empty_think_block_then_json_parses():
    """/no_think yields an empty <think></think> then the JSON — must parse."""
    a = LocalAnalyzer.__new__(LocalAnalyzer)
    raw = '<think>\n\n</think>\n\n{"attack_narrative": "x", "confidence": 60}'
    out = a._parse_json(raw)
    assert out["attack_narrative"] == "x"
    assert out["confidence"] == 60
