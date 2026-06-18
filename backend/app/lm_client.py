"""
LM Studio Client — shared helper for all local LLM calls.

Handles:
  - OpenAI-compatible API (/v1/chat/completions) — default
  - LM Studio REST API v1 (/api/v1/chat) — fallback
  - Automatic endpoint detection on first call
  - Model listing and health checks
"""

import json
import logging
from typing import Any

import httpx  # type: ignore[import]

from app.config import get_settings

logger = logging.getLogger(__name__)


class LMStudioClient:
    """Unified client for LM Studio, auto-detects API format."""

    def __init__(self):
        self.settings = get_settings()
        # Base host without /v1 suffix
        raw = self.settings.lm_studio_base_url.rstrip("/")
        self._host = raw.removesuffix("/v1")
        self._api_format: str | None = None  # "openai" or "lmstudio"

    async def _detect_api(self) -> str:
        """Detect which API format LM Studio supports."""
        if self._api_format:
            return self._api_format

        async with httpx.AsyncClient(timeout=10.0) as client:
            # Try OpenAI-compatible first (most common)
            try:
                r = await client.get(f"{self._host}/v1/models")
                if r.status_code == 200:
                    self._api_format = "openai"
                    logger.info("LM Studio API: using OpenAI-compatible format")
                    return "openai"
            except Exception:
                pass

            # Try LM Studio REST API v1
            try:
                r = await client.get(f"{self._host}/api/v1/models")
                if r.status_code == 200:
                    self._api_format = "lmstudio"
                    logger.info("LM Studio API: using LM Studio REST API v1 format")
                    return "lmstudio"
            except Exception:
                pass

        # Default to OpenAI format
        self._api_format = "openai"
        return "openai"

    def _chat_url(self) -> str:
        if self._api_format == "lmstudio":
            return f"{self._host}/api/v1/chat"
        return f"{self._host}/v1/chat/completions"

    def _models_url(self) -> str:
        if self._api_format == "lmstudio":
            return f"{self._host}/api/v1/models"
        return f"{self._host}/v1/models"

    async def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int = 6000,
        timeout: float = 300.0,
        tools: list[dict] | None = None,
    ) -> str:
        """
        Send a chat completion request to LM Studio.
        Auto-retries with truncated input on 400 (context length exceeded).

        If `tools` is provided, returns the full message dict (so callers can
        read tool_calls); otherwise returns the response text as before.
        """
        await self._detect_api()

        # Try with progressively shorter input on 400 errors
        for attempt, shrink in enumerate([1.0, 0.5, 0.25]):
            truncated_messages = messages
            if shrink < 1.0:
                truncated_messages = []
                for msg in messages:
                    content = msg["content"]
                    max_len = int(len(content) * shrink)
                    truncated_messages.append({
                        "role": msg["role"],
                        "content": content[:max_len],
                    })
                logger.info(f"Retry {attempt}: truncated input to {shrink:.0%}")

            payload: dict[str, Any] = {
                "model": self.settings.lm_studio_model,
                "messages": truncated_messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            }
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"

            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(self._chat_url(), json=payload)

                if resp.status_code == 400:
                    # Read the real error instead of assuming "input too long" —
                    # LM Studio also returns 400 for "model not found", malformed
                    # tool schemas, etc. Blindly truncating on every 400 hides
                    # those errors behind a misleading retry loop.
                    try:
                        body = resp.json()
                        err_msg = body.get("error", {}).get("message", "") if isinstance(
                            body.get("error"), dict
                        ) else str(body.get("error", body))
                    except Exception:
                        err_msg = resp.text[:300]

                    context_related = any(
                        kw in err_msg.lower()
                        for kw in ("context", "token", "too long", "maximum length")
                    )

                    if context_related and shrink > 0.25:
                        logger.warning(
                            f"LM Studio 400 (context length, attempt {attempt+1}): "
                            f"{err_msg}. Retrying with shorter input..."
                        )
                        continue

                    # Not a context-length issue (or we're out of retries) —
                    # surface the real reason immediately.
                    logger.error(
                        f"LM Studio 400 — not a context-length issue, won't retry blindly: "
                        f"{err_msg}"
                    )

                resp.raise_for_status()
                result = resp.json()
                message = result["choices"][0]["message"]
                # When tools are in play, return the whole message so the
                # caller can inspect tool_calls (native function calling).
                if tools:
                    return message
                return (message.get("content") or "").strip()

        raise Exception("LM Studio rejected input even after truncation. "
                       "Increase context length in LM Studio settings.")

    async def health_check(self) -> bool:
        """Check if LM Studio is running and has a model loaded."""
        try:
            await self._detect_api()
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self._models_url())
                if resp.status_code != 200:
                    return False
                models = resp.json()
                return len(models.get("data", [])) > 0
        except Exception:
            return False

    async def get_loaded_model(self) -> str | None:
        """Return the currently loaded model ID."""
        try:
            await self._detect_api()
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(self._models_url())
                if resp.status_code == 200:
                    models = resp.json().get("data", [])
                    if models:
                        return models[0].get("id", "unknown")
        except Exception:
            pass
        return None


# Singleton
_client: LMStudioClient | None = None

def get_lm_client() -> LMStudioClient:
    global _client
    if _client is None:
        _client = LMStudioClient()
    return _client