"""
Tests for parsing JSON out of reasoning-model output.

DeepSeek-R1 / QwQ / other reasoning models prepend a <think>...</think>
chain-of-thought block before the JSON answer. That block is prose and often
contains stray braces, which broke the old parser two ways:
  1. The response didn't start with '{', so the first json.loads failed.
  2. The greedy {.*} regex grabbed from the first brace in the THINK block to
     the last brace anywhere, producing garbage.
These tests lock in that both are handled.
"""
import json

from app.local_analyzer import LocalAnalyzer


def _analyzer():
    return LocalAnalyzer.__new__(LocalAnalyzer)


def test_parses_json_after_think_block():
    a = _analyzer()
    raw = (
        "<think>\nOkay, the user wants attack_narrative. Let me consider "
        "{this} and {that}. I'll produce the JSON now.\n</think>\n"
        '{"attack_narrative": "Mimikatz observed", "confidence": 80}'
    )
    out = a._parse_json(raw)
    assert out["attack_narrative"] == "Mimikatz observed"
    assert out["confidence"] == 80


def test_parses_json_with_unclosed_think():
    """Degenerate case: model opened <think> but the close tag is missing."""
    a = _analyzer()
    raw = '<think> reasoning... {stray} \n{"key_findings": [], "confidence": 50}'
    out = a._parse_json(raw)
    assert out["confidence"] == 50


def test_balanced_extraction_ignores_trailing_prose():
    """A second brace group after the object must not extend the match."""
    a = _analyzer()
    raw = (
        '{"attack_narrative": "ok", "confidence": 70}\n\n'
        "Note: also see {unrelated: braces} below."
    )
    out = a._parse_json(raw)
    assert out["attack_narrative"] == "ok"
    assert out["confidence"] == 70


def test_plain_json_still_works():
    """Non-reasoning models (plain JSON) must keep parsing as before."""
    a = _analyzer()
    out = a._parse_json('{"attack_narrative": "x", "confidence": 60}')
    assert out["confidence"] == 60


def test_fenced_json_after_think():
    """Reasoning block + ```json fence combined."""
    a = _analyzer()
    raw = (
        "<think>thinking</think>\n```json\n"
        '{"attack_narrative": "fenced", "confidence": 65}\n```'
    )
    out = a._parse_json(raw)
    assert out["attack_narrative"] == "fenced"


def test_garbage_returns_empty_dict():
    a = _analyzer()
    assert a._parse_json("no json here at all") == {}


def test_balanced_extractor_directly():
    a = _analyzer()
    assert a._extract_balanced_json('x {"a": 1} y') == '{"a": 1}'
    assert a._extract_balanced_json('{"a": {"b": 2}} tail') == '{"a": {"b": 2}}'
    # Brace inside a string must not be miscounted.
    assert json.loads(a._extract_balanced_json('{"a": "has } brace"}')) == {"a": "has } brace"}
    assert a._extract_balanced_json("no braces") is None
