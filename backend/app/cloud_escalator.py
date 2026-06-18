"""
Claude Analyzer — MINIMAL cloud usage.

Only called when the local LLM identifies specific knowledge gaps it cannot fill.
Receives anonymized, targeted questions — never raw forensic dumps.

Typical escalation reasons:
  - Unknown file hashes that need threat intel lookup
  - Unfamiliar malware families or C2 frameworks
  - Recent CVE details not in local model training data
  - Novel attack patterns needing attribution context
  - Detection rule suggestions for specific TTPs
"""

import json
import re
import logging

import anthropic

from app.config import get_settings
from app.models import EscalationItem

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a cybersecurity threat intelligence specialist.
You will receive SPECIFIC questions from a local incident response system that
has already performed primary analysis. Your job is to fill knowledge gaps.

The data has been anonymized — work with placeholder values.

For each question, provide:
1. A direct answer using your knowledge
2. Confidence level (0-1)
3. Any additional context that would help the local analyst

You have access to extensive threat intelligence training data including:
- Known malware families, C2 frameworks, and TTPs
- CVE details and exploit chains
- APT group attributions and campaigns
- YARA/Sigma detection rule patterns
- Remediation best practices

Respond ONLY with a JSON object:
{
  "answers": [
    {
      "question_index": 0,
      "answer": "detailed answer",
      "confidence": 0.0-1.0,
      "additional_context": "optional extra info",
      "references": ["any known references like CVE IDs, malware family names, etc."]
    }
  ],
  "meta": {
    "questions_answered": 3,
    "questions_uncertain": 1
  }
}

If you genuinely don't know, say so — don't fabricate threat intel."""


class CloudEscalator:
    """Sends targeted questions to Claude when the local LLM has knowledge gaps."""

    # Stale/invalid model strings → current valid replacement
    MODEL_CORRECTIONS = {
        "claude-sonnet-4-20250514": "claude-sonnet-4-6",
        "claude-sonnet-4-5-20250929": "claude-sonnet-4-6",
        "claude-3-5-sonnet-20241022": "claude-sonnet-4-6",
        "claude-3-5-sonnet-latest": "claude-sonnet-4-6",
    }

    def __init__(self):
        self.settings = get_settings()
        self._client: anthropic.Anthropic | None = None

    def _resolve_model(self) -> str:
        """Return a valid model string, auto-correcting known-stale names."""
        model = self.settings.claude_model
        corrected = self.MODEL_CORRECTIONS.get(model)
        if corrected:
            logger.warning(
                f"Model '{model}' is outdated/invalid — using '{corrected}'. "
                f"Update CLAUDE_MODEL in your .env to silence this."
            )
            return corrected
        return model

    def _get_client(self) -> anthropic.Anthropic:
        if self._client is None:
            self._client = anthropic.Anthropic(
                api_key=self.settings.anthropic_api_key
            )
        return self._client

    async def escalate(self, items: list[EscalationItem],
                       incident_summary: str = "") -> list[EscalationItem]:
        """
        Send knowledge gaps to Claude for answers.
        Returns the items updated with cloud answers.

        This is the ONLY function that contacts Claude. The caller
        (orchestrator) anonymizes the questions, context, and summary right
        before invoking this, and de-anonymizes the answers as soon as they
        return — so everything crossing this boundary is already anonymized.

        It does NOT send raw forensic data.
        """
        if not items:
            return []

        if not self.health_check():
            logger.warning("Claude API not configured, skipping escalation")
            return items

        # Build the question payload — keep it minimal
        questions_text = []
        for i, item in enumerate(items):
            questions_text.append(
                f"Question {i} [{item.category}] (priority: {item.priority}):\n"
                f"{item.question}\n"
                f"Context: {item.context[:500] if item.context else 'none'}"
            )

        user_message = (
            f"Incident summary (anonymized): {incident_summary[:1000]}\n\n"
            f"The local analysis system has {len(items)} knowledge gaps:\n\n"
            + "\n\n".join(questions_text)
        )

        try:
            logger.info(
                f"Escalating {len(items)} questions to Claude "
                f"({len(user_message)} chars)"
            )

            client = self._get_client()
            message = client.messages.create(
                model=self._resolve_model(),
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                messages=[{"role": "user", "content": user_message}],
            )

            raw = message.content[0].text
            logger.info(f"Cloud response: {len(raw)} chars")

            return self._apply_answers(items, raw)

        except anthropic.NotFoundError as e:
            logger.error(f"Claude model not found: {e}")
            raise ValueError(
                f"Claude model '{self._resolve_model()}' not found. "
                f"Check CLAUDE_MODEL in .env — valid options include "
                f"claude-sonnet-4-6, claude-opus-4-1, claude-haiku-4-5-20251001."
            )
        except anthropic.AuthenticationError as e:
            logger.error(f"Claude auth error: {e}")
            raise ValueError("Claude API key is invalid. Check ANTHROPIC_API_KEY in .env.")
        except anthropic.APIError as e:
            logger.error(f"Claude API error during escalation: {e}")
            raise ValueError(f"Claude API error: {e}")
        except Exception as e:
            logger.error(f"Unexpected cloud escalation error: {e}")
            raise

    def _apply_answers(self, items: list[EscalationItem], raw: str) -> list[EscalationItem]:
        """Parse Claude's response and update escalation items."""
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("Could not parse cloud response as JSON")
            # Store raw response on all items
            for item in items:
                item.cloud_answer = raw[:500]
            return items

        for answer in data.get("answers", []):
            idx = answer.get("question_index", -1)
            if 0 <= idx < len(items):
                items[idx].cloud_answer = answer.get("answer", "")
                items[idx].resolved_by_cloud = answer.get("confidence", 0) >= 0.5

                # Append references to the answer
                refs = answer.get("references", [])
                if refs:
                    items[idx].cloud_answer += f"\nReferences: {', '.join(refs)}"

                extra = answer.get("additional_context", "")
                if extra:
                    items[idx].cloud_answer += f"\nAdditional: {extra}"

        resolved = sum(1 for item in items if item.resolved_by_cloud)
        logger.info(f"Cloud resolved {resolved}/{len(items)} escalation items")

        return items

    def health_check(self) -> bool:
        """Check if Claude API key is configured."""
        key = self.settings.anthropic_api_key
        return bool(key and key != "sk-ant-XXXXXXXXXXXXXXXXXXXXX" and len(key) > 20)

    def estimate_cost(self, items: list[EscalationItem]) -> dict:
        """
        Rough cost estimate for escalation.
        Helps the analyst decide whether to approve cloud usage.
        """
        total_chars = sum(
            len(item.question) + len(item.context)
            for item in items
        )
        # Rough estimate: ~4 chars per token, input + output
        est_input_tokens = total_chars / 4 + 500  # system prompt overhead
        est_output_tokens = len(items) * 200  # ~200 tokens per answer

        # Claude Sonnet pricing (approximate)
        input_cost = (est_input_tokens / 1_000_000) * 3.0
        output_cost = (est_output_tokens / 1_000_000) * 15.0

        return {
            "estimated_input_tokens": int(est_input_tokens),
            "estimated_output_tokens": int(est_output_tokens),
            "estimated_cost_usd": round(input_cost + output_cost, 4),
            "questions_count": len(items),
        }
