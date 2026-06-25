"""
Tests for the baseline LLM call timeout.

Regression for the Pass-1 (primary analysis) ReadTimeout: that call didn't
pass a timeout, so it used httpx's short 300s default and got cut off while
DeepSeek-R1 was still reasoning (~170s) on a large prompt. _call_llm now falls
back to the configured llm_timeout for every call that doesn't specify one.
"""
import inspect

import pytest

from app.config import Settings
from app.local_analyzer import LocalAnalyzer


def test_config_has_baseline_llm_timeout():
    s = Settings()
    # Generous enough for a slow reasoning model's full think+generate cycle.
    assert s.llm_timeout >= 300
    # Narrative pass keeps its own (>=) timeout.
    assert s.narrative_timeout >= s.llm_timeout or s.narrative_timeout >= 300


@pytest.mark.asyncio
async def test_call_llm_defaults_timeout_to_config():
    """When no timeout is passed, _call_llm uses settings.llm_timeout."""
    captured = {}

    async def fake_chat(**kwargs):
        captured.update(kwargs)
        return "{}"

    a = LocalAnalyzer.__new__(LocalAnalyzer)
    class _LM:
        chat = staticmethod(fake_chat)
    a.lm = _LM()

    await a._call_llm("sys", "user")
    assert captured.get("timeout")
    assert captured["timeout"] >= 300


@pytest.mark.asyncio
async def test_call_llm_explicit_timeout_wins():
    """An explicit timeout (e.g. the narrative pass's) overrides the default."""
    captured = {}

    async def fake_chat(**kwargs):
        captured.update(kwargs)
        return "{}"

    a = LocalAnalyzer.__new__(LocalAnalyzer)
    class _LM:
        chat = staticmethod(fake_chat)
    a.lm = _LM()

    await a._call_llm("sys", "user", timeout=999)
    assert captured["timeout"] == 999
