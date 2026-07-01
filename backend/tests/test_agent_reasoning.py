"""
Tests that the investigation agent survives a reasoning model returning empty
content — the DeepSeek-R1 failure where the whole token budget goes to <think>
and finish_reason=length, leaving content="" and no tool_calls. That showed up
as the chat producing no answer at all.
"""
import pytest

from app.investigation_agent import InvestigationAgent, CHAT_SYSTEM_PROMPT, SYSTEM_PROMPT


def test_no_think_in_prompts():
    # Both the interactive and the autonomous prompts disable thinking.
    assert "/no_think" in CHAT_SYSTEM_PROMPT
    assert "/no_think" in SYSTEM_PROMPT


@pytest.mark.asyncio
async def test_empty_native_content_signals_fallback():
    """An empty assistant message (no content, no tool_calls) must not become a
    blank answer — _call_native returns None so the loop can retry/fall back."""
    async def fake_llm(history, tools=None):
        return {"role": "assistant", "content": "", "tool_calls": []}

    class _Tools: ...
    agent = InvestigationAgent(fake_llm, _Tools(), use_native_tools=True)
    decision = await agent._call_native([{"role": "user", "content": "hi"}])
    assert decision is None
    assert agent._native_failed is True


@pytest.mark.asyncio
async def test_native_tool_call_still_works():
    """A proper tool call is still parsed normally."""
    async def fake_llm(history, tools=None):
        return {
            "role": "assistant", "content": "checking",
            "tool_calls": [{"id": "c1", "function": {"name": "search",
                            "arguments": '{"query": "IP"}'}}],
        }

    class _Tools: ...
    agent = InvestigationAgent(fake_llm, _Tools(), use_native_tools=True)
    decision = await agent._call_native([{"role": "user", "content": "find IPs"}])
    assert decision["action"] == "search"
    assert decision["args"] == {"query": "IP"}


@pytest.mark.asyncio
async def test_native_text_answer_passes_through():
    """Non-empty content with no tool call is a valid natural-language answer."""
    async def fake_llm(history, tools=None):
        return {"role": "assistant", "content": "No IP addresses were found.",
                "tool_calls": []}

    class _Tools: ...
    agent = InvestigationAgent(fake_llm, _Tools(), use_native_tools=True)
    decision = await agent._call_native([{"role": "user", "content": "find IPs"}])
    assert decision["action"] == "answer"
    assert "No IP addresses" in decision["answer"]
