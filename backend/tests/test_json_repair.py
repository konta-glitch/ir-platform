"""
Tests for the json-repair fallback in _parse_json.

DeepSeek-R1 occasionally emits a narrative batch with a minor JSON syntax
error (a missing ':' or ',', an unclosed quote) — the real failure observed
was 'Expecting ':' delimiter'. json-repair recovers these as a last resort,
after strict json.loads and the brace-balanced extractor have failed, so a
single malformed batch no longer drops its entire narrative.
"""
from app.local_analyzer import LocalAnalyzer


def _a():
    return LocalAnalyzer.__new__(LocalAnalyzer)


def test_recovers_missing_colon():
    """The actual failure: a missing ':' after a key."""
    a = _a()
    broken = '{"summary": "x", "severity" "critical", "confidence": 0.8}'
    out = a._parse_json(broken)
    assert out["severity"] == "critical"
    assert out["confidence"] == 0.8


def test_recovers_trailing_comma():
    a = _a()
    broken = '{"a": 1, "b": 2,}'
    out = a._parse_json(broken)
    assert out == {"a": 1, "b": 2}


def test_recovers_unclosed_quote():
    a = _a()
    broken = '{"summary": "unterminated, "confidence": 0.5}'
    out = a._parse_json(broken)
    # Whatever json-repair makes of it, it must be a non-empty dict, not {}.
    assert isinstance(out, dict) and out


def test_recovers_after_think_block_with_broken_json():
    """Reasoning prefix + a structurally broken JSON answer."""
    a = _a()
    raw = '<think>reasoning</think>\n{"attack_narrative": "y" "confidence": 60}'
    out = a._parse_json(raw)
    assert out.get("attack_narrative") == "y"


def test_valid_json_still_uses_fast_path():
    """Well-formed JSON parses unchanged (json-repair not needed)."""
    a = _a()
    out = a._parse_json('{"attack_narrative": "ok", "confidence": 70}')
    assert out == {"attack_narrative": "ok", "confidence": 70}


def test_pure_garbage_returns_empty_dict():
    a = _a()
    assert a._parse_json("this is not json at all, just prose") == {}
