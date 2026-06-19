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

import httpx

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

    @staticmethod
    def _merge_system_into_user(messages: list[dict]) -> list[dict]:
        """
        Some chat templates (notably the stock Mixtral-Instruct Jinja
        template in LM Studio) reject a separate "system" role outright —
        "Only user and assistant roles are supported!" — even though the
        OpenAI-compatible API accepts the request structurally. The fix is
        to fold any system message into the start of the first user message,
        which every template accepts since it's just plain user content.
        """
        if not messages or messages[0].get("role") != "system":
            return messages
        system_content = messages[0]["content"]
        rest = messages[1:]
        if rest and rest[0].get("role") == "user":
            merged_first = {
                "role": "user",
                "content": f"{system_content}\n\n{rest[0]['content']}",
            }
            return [merged_first] + rest[1:]
        # No user message to merge into (unusual) — drop the system role
        # rather than send a structure we already know this template rejects.
        return [{"role": "user", "content": system_content}] + rest

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
        Auto-retries once with system+user merged on 400 (template rejects
        the system role — see _merge_system_into_user).

        If `tools` is provided, returns the full message dict (so callers can
        read tool_calls); otherwise returns the response text as before.
        """
        await self._detect_api()
        active_messages = messages
        merged_for_template = False
        # Tracks shrink ratio independently of `attempt`, so a template merge
        # doesn't accidentally inherit whatever shrink the truncation-retry
        # loop was on. Without this, merging on attempt=0 (shrink=1.0) and
        # then incrementing attempt to 1 would apply shrink_schedule[1]=0.5
        # to the freshly-merged message — silently truncating content the
        # context-length logic never determined was too long. This was a
        # real bug: every Mixtral call was being truncated to 50% on the
        # merge-retry, regardless of whether the content actually needed it.
        current_shrink = 1.0

        # Try with progressively shorter input on 400 errors. The template
        # merge (system role rejected) gets one extra pass appended after
        # the truncation budget runs out, since it's an orthogonal fix —
        # without this, hitting "system role rejected" on the LAST
        # truncation attempt would silently fall through to the final
        # error instead of getting its one merge-and-retry chance.
        shrink_schedule = [1.0, 0.5, 0.25]
        attempt = 0
        while attempt < len(shrink_schedule) or merged_for_template is False:
            shrink = current_shrink

            truncated_messages = active_messages
            if shrink < 1.0:
                truncated_messages = []
                for msg in active_messages:
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
                    template_rejects_system = (
                        "only user and assistant roles" in err_msg.lower()
                        or ("jinja" in err_msg.lower() and "role" in err_msg.lower())
                    )

                    if template_rejects_system and not merged_for_template:
                        # Independent of the truncation budget — always get
                        # this one chance, even if shrink_schedule is spent.
                        #
                        # Shrink-level handling: if NO context-length retry
                        # has happened yet (current_shrink is still 1.0), the
                        # merge is the only transformation needed — send the
                        # full merged content. But if a context-length retry
                        # already legitimately shrunk the content (the model
                        # proved it couldn't handle the full size), KEEP that
                        # shrink level through the merge rather than resetting
                        # to 1.0 — sending full-size content again would just
                        # reproduce the context-length error we already fixed.
                        logger.warning(
                            f"LM Studio 400 (chat template rejects system role): "
                            f"{err_msg}. Merging system into user message and retrying "
                            f"(preserving current shrink={current_shrink:.0%})..."
                        )
                        active_messages = self._merge_system_into_user(active_messages)
                        merged_for_template = True
                        attempt += 1
                        continue

                    if context_related and attempt < len(shrink_schedule) - 1:
                        attempt += 1
                        current_shrink = shrink_schedule[attempt]
                        logger.warning(
                            f"LM Studio 400 (context length, attempt {attempt}): "
                            f"{err_msg}. Retrying with shorter input..."
                        )
                        continue

                    # Not a context-length or known-template issue (or we're
                    # out of retries) — surface the real reason immediately.
                    logger.error(
                        f"LM Studio 400 — not a context-length issue, won't retry blindly: "
                        f"{err_msg}"
                    )
                    # Neither retry condition matched (or both are exhausted)
                    # — force loop exit via the guard below rather than
                    # looping forever on the same failing request.
                    attempt = len(shrink_schedule)
                    merged_for_template = True

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