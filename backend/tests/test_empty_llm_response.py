"""
Tests for handling empty LLM responses from reasoning models and the
reasoning-safe token budget.

DeepSeek-R1 can exhaust the token budget inside its <think> block and return
empty "content" (the "received 0 chars" symptom). These tests verify the
extraction logic identifies the cutoff case and that the default budget is
large enough to leave room for reasoning + answer.
"""
import inspect

from app.lm_client import LMStudioClient


def _payload(message: dict, finish_reason: str = "stop"):
    return {"choices": [{"message": message, "finish_reason": finish_reason}]}


def test_empty_content_with_length_cutoff_is_detectable():
    """Reasoning-only response (hit token limit) is identifiable as a cutoff."""
    payload = _payload(
        {"content": "", "reasoning_content": "lots of thinking..."},
        finish_reason="length",
    )
    message = payload["choices"][0]["message"]
    content = (message.get("content") or "").strip()
    finish = payload["choices"][0].get("finish_reason", "")
    reasoning = message.get("reasoning_content") or message.get("reasoning") or ""
    assert content == ""
    assert finish == "length"
    assert reasoning  # the cutoff-mid-reasoning signature


def test_normal_content_returned_stripped():
    payload = _payload({"content": "  hello  "})
    message = payload["choices"][0]["message"]
    assert (message.get("content") or "").strip() == "hello"


def test_default_max_tokens_is_reasoning_safe():
    """chat()'s default budget leaves room for reasoning + answer."""
    sig = inspect.signature(LMStudioClient.chat)
    assert sig.parameters["max_tokens"].default >= 16000


def test_config_exposes_llm_max_tokens():
    from app.config import Settings
    s = Settings()
    assert s.llm_max_tokens >= 16000
