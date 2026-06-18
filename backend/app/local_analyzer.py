"""
Local Analyzer — runs the primary IR analysis on LM Studio.

This is the workhorse of the platform. The local LLM handles:
  - IOC extraction (IPs, domains, hashes, filenames, registry keys)
  - MITRE ATT&CK technique mapping
  - Timeline reconstruction
  - Severity assessment
  - Containment recommendations
  - Confidence self-assessment per finding

The confidence scores drive the escalation decision:
  - High confidence (≥0.7) → finding stays as-is
  - Low confidence (<0.7) → gets queued for Claude verification
"""

import json
import re
import logging
from typing import Any

from app.config import get_settings
from app.lm_client import get_lm_client
from app.models import (
    AnalysisResult,
    IOC,
    MITRETechnique,
    Severity,
    TimelineEntry,
    EscalationItem,
)

logger = logging.getLogger(__name__)

ANALYSIS_SYSTEM_PROMPT = """You are an expert cybersecurity incident responder and forensic analyst
running LOCALLY on the analyst's machine. You have been given anonymized forensic data.

Perform a thorough analysis and return ONLY a JSON object with this structure:
{
  "summary": "2-3 sentence executive summary of what happened",
  "severity": "critical|high|medium|low|info",
  "severity_justification": "why you chose this severity",

  "iocs": [
    {
      "type": "ip|domain|hash_md5|hash_sha256|url|email|filename|registry_key|service_name",
      "value": "the indicator value",
      "context": "where/how it was observed",
      "confidence": 0.0-1.0,
      "malicious": true|false,
      "confidence_reason": "why this confidence level"
    }
  ],

  "mitre_techniques": [
    {
      "technique_id": "Txxxx.xxx",
      "technique_name": "Name",
      "tactic": "initial-access|execution|persistence|privilege-escalation|defense-evasion|credential-access|discovery|lateral-movement|collection|exfiltration|command-and-control|impact",
      "confidence": 0.0-1.0,
      "evidence": "specific evidence from the data"
    }
  ],

  "timeline": [
    {
      "timestamp": "ISO or relative timestamp",
      "event": "what happened",
      "source": "which data source showed this",
      "significance": "why it matters"
    }
  ],

  "recommendations": ["concrete actionable steps"],

  "knowledge_gaps": [
    {
      "question": "specific question you cannot answer with your training data",
      "category": "threat_intel|malware_family|cve_details|attribution|detection_rule|remediation",
      "context": "relevant anonymized data for this question",
      "priority": "high|medium|low"
    }
  ],

  "overall_confidence": 0.0-1.0,
  "confidence_explanation": "what you're sure about and what you're not"
}

IMPORTANT RULES:
- Be HONEST about confidence. If you don't recognize a hash, say so.
- knowledge_gaps should list SPECIFIC things a cloud LLM with internet access could help with.
- Do NOT fabricate threat intel. If you don't know a malware family, set confidence low and add it to gaps.
- For unknown hashes/domains, always flag as a gap — the cloud model can check threat feeds.
- Common TTPs (powershell execution, scheduled tasks, etc.) you know well — high confidence.
- Novel or sophisticated attack patterns — lower confidence, flag for review.
- Respond ONLY with the JSON object, no markdown fences, no preamble."""


ENRICHMENT_PROMPT = """You are a local cybersecurity analyst. Given partial analysis results,
answer the following specific questions using ONLY your training knowledge.
If you don't know, say "UNKNOWN" — do not guess.

Return ONLY a JSON object:
{
  "answers": [
    {
      "question_index": 0,
      "answer": "your answer or UNKNOWN",
      "confidence": 0.0-1.0,
      "still_needs_cloud": true|false
    }
  ]
}"""


class LocalAnalyzer:
    """Primary IR analysis engine running on LM Studio."""

    def __init__(self):
        self.settings = get_settings()
        self.lm = get_lm_client()

    async def _call_llm(self, system: str, user: str,
                        temperature: float = 0.1,
                        max_tokens: int = 6000) -> str:
        """Call the local LLM via LM Studio (auto-detects API format)."""
        return await self.lm.chat(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )

    async def chat_messages(self, messages: list[dict],
                            temperature: float = 0.2,
                            max_tokens: int = 1500,
                            tools: list[dict] | None = None):
        """Multi-turn chat — used by the investigation agent's reasoning loop.

        With `tools`, returns the full assistant message dict (may contain
        tool_calls) for native function calling. Without, returns text.
        """
        return await self.lm.chat(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
        )

    async def generate_narrative(self, findings: list[dict],
                                  attack_chains: list[str],
                                  context: str = "") -> dict:
        """
        Second LLM pass: generate an attack narrative + per-finding triage
        for the top findings. Puts more LLM reasoning into the final report.
        """
        if not findings:
            return {}

        top = findings[:25]
        finding_lines = []
        for f in top:
            ev = f.get("evidence", {})
            locator = ev.get("locator", f.get("artifact", ""))
            finding_lines.append(
                f"[{f['id']}] {f['severity'].upper()} {f['title']} "
                f"(MITRE {f.get('mitre', 'N/A')}) — {f['description'][:150]} "
                f"[evidence: {locator}]"
            )
        findings_text = "\n".join(finding_lines)
        chains_text = "\n".join(f"- {c}" for c in attack_chains) or "None detected"

        system = """You are a senior incident responder writing the analysis section of an IR report.
You are RIGOROUS about false positives — automated detections are leads, not conclusions.

Given automated detection findings, produce a JSON object with:
{
  "attack_narrative": "2-4 paragraph plain-language story of what likely happened, in logical order, referencing finding IDs like [F0001]. If the evidence is weak or ambiguous, SAY SO rather than inventing an attack.",
  "key_findings": [{"finding_id": "F0001", "why_it_matters": "1-2 sentences", "recommended_action": "specific action", "assessment": "true_positive | likely_benign | needs_review"}],
  "likely_false_positives": [{"finding_id": "F0002", "reason": "why this is probably benign"}],
  "threat_assessment": "1 paragraph: severity, attacker sophistication, likely objective — calibrated to the ACTUAL evidence strength",
  "confidence": 0.0-1.0
}

Critical guidance to avoid false positives:
- Many Sigma matches are low-fidelity (a tool CAN be misused, not that it WAS). Weigh them lightly unless corroborated.
- A single finding type repeated many times (high occurrence count) is often noise or normal system behavior, not N separate attacks.
- Distinguish "an attacker did X" from "X is technically possible here". Only claim compromise when evidence corroborates across artifacts (e.g. process tree + network + log clearing together).
- If findings are mostly isolated medium-severity Sigma hits with no corroboration, the honest verdict is "suspicious indicators requiring review", NOT "active compromise".
- Reference finding IDs in brackets. Technical but readable. Output ONLY valid JSON."""

        user = f"""Analyst context: {context}

Detected attack chains:
{chains_text}

Top findings:
{findings_text}

Write the IR analysis as JSON. Be rigorous: separate corroborated true positives from
isolated low-confidence hits, and calibrate your confidence to the actual evidence."""

        try:
            logger.info(f"Narrative pass: analyzing {len(top)} findings via LLM")
            raw = await self._call_llm(system, user, temperature=0.2, max_tokens=2500)
            result = self._parse_json(raw)
            if result:
                logger.info("Narrative pass: generated attack narrative")
            return result
        except Exception as e:
            logger.warning(f"Narrative generation failed: {e}")
            return {}

    def _parse_json(self, text: str) -> dict:
        """Safely parse JSON from LLM output."""
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse failed: {e}")
            # Try to extract JSON from the text
            match = re.search(r'\{[\s\S]*\}', cleaned)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
            return {}

    async def analyze(self, anonymized_data: str, context: str = "",
                      data_type: str = "general") -> tuple[AnalysisResult, list[EscalationItem]]:
        """
        Run primary analysis on the local LLM.

        Returns:
            tuple of (AnalysisResult, list of EscalationItems needing cloud review)
        """
        user_message = f"""Analyze this anonymized forensic data.

Data type: {data_type}
{f"Analyst context: {context}" if context else ""}

--- BEGIN DATA ---
{anonymized_data[:12000]}
--- END DATA ---"""

        logger.info(f"Local analysis: sending {len(anonymized_data)} chars to LM Studio")
        raw = await self._call_llm(ANALYSIS_SYSTEM_PROMPT, user_message)
        logger.info(f"Local analysis: received {len(raw)} chars")

        data = self._parse_json(raw)
        if not data:
            return AnalysisResult(
                summary="Local analysis failed to produce structured output",
                severity=Severity.INFO,
                raw_response=raw,
            ), []

        # Build IOCs
        iocs = []
        for ioc_data in data.get("iocs", []):
            try:
                iocs.append(IOC(**ioc_data))
            except Exception:
                continue

        # Build MITRE techniques
        techniques = []
        for tech_data in data.get("mitre_techniques", []):
            try:
                techniques.append(MITRETechnique(**tech_data))
            except Exception:
                continue

        # Build timeline
        timeline = []
        for entry_data in data.get("timeline", []):
            try:
                timeline.append(TimelineEntry(**entry_data))
            except Exception:
                continue

        # Severity
        try:
            severity = Severity(data.get("severity", "medium").lower())
        except ValueError:
            severity = Severity.MEDIUM

        analysis = AnalysisResult(
            summary=data.get("summary", ""),
            severity=severity,
            iocs=iocs,
            mitre_techniques=techniques,
            recommendations=data.get("recommendations", []),
            timeline=timeline,
            overall_confidence=data.get("overall_confidence", 0.5),
            confidence_explanation=data.get("confidence_explanation", ""),
            raw_response=raw,
        )

        # Extract escalation items (knowledge gaps)
        escalation_items = []
        for gap in data.get("knowledge_gaps", []):
            try:
                escalation_items.append(EscalationItem(
                    question=gap["question"],
                    category=gap.get("category", "general"),
                    context=gap.get("context", ""),
                    priority=gap.get("priority", "medium"),
                ))
            except Exception:
                continue

        # Also escalate low-confidence IOCs
        for ioc in iocs:
            if ioc.confidence < 0.5 and ioc.type in ("hash_md5", "hash_sha256", "domain", "ip"):
                escalation_items.append(EscalationItem(
                    question=f"Is this {ioc.type} known malicious? Value: {ioc.value}",
                    category="threat_intel",
                    context=ioc.context,
                    priority="high" if ioc.type.startswith("hash") else "medium",
                ))

        # Escalate low-confidence MITRE techniques
        for tech in techniques:
            if tech.confidence < 0.5:
                escalation_items.append(EscalationItem(
                    question=f"Confirm {tech.technique_id} ({tech.technique_name}): {tech.evidence}",
                    category="attribution",
                    context=tech.evidence,
                    priority="medium",
                ))

        logger.info(
            f"Local analysis complete: {len(iocs)} IOCs, {len(techniques)} MITRE techniques, "
            f"{len(escalation_items)} items flagged for escalation, "
            f"overall confidence: {analysis.overall_confidence}"
        )

        return analysis, escalation_items

    async def try_answer_gaps(self, gaps: list[EscalationItem],
                               analysis_context: str) -> list[EscalationItem]:
        """
        Second local pass — try to answer knowledge gaps with more focused prompts.
        Returns only the gaps that still need cloud escalation.
        """
        if not gaps:
            return []

        questions = "\n".join(
            f"{i}. [{g.category}] {g.question}"
            for i, g in enumerate(gaps)
        )

        user_msg = f"""Based on this incident context:
{analysis_context[:5000]}

Try to answer these specific questions:
{questions}"""

        try:
            raw = await self._call_llm(ENRICHMENT_PROMPT, user_msg, max_tokens=3000)
            data = self._parse_json(raw)

            remaining = []
            for answer in data.get("answers", []):
                idx = answer.get("question_index", -1)
                if 0 <= idx < len(gaps):
                    if answer.get("still_needs_cloud", True):
                        remaining.append(gaps[idx])
                    else:
                        # Local model answered it — store the answer
                        gaps[idx].local_answer = answer.get("answer", "")
                        gaps[idx].resolved_locally = True

            # Add any gaps that weren't addressed
            addressed_indices = {a.get("question_index") for a in data.get("answers", [])}
            for i, gap in enumerate(gaps):
                if i not in addressed_indices:
                    remaining.append(gap)

            logger.info(
                f"Second local pass: {len(gaps) - len(remaining)} gaps resolved locally, "
                f"{len(remaining)} still need cloud"
            )
            return remaining

        except Exception as e:
            logger.warning(f"Second local pass failed: {e}, escalating all gaps")
            return gaps

    async def health_check(self) -> bool:
        """Check if LM Studio is running and has a model loaded."""
        return await self.lm.health_check()

    async def get_loaded_model(self) -> str | None:
        """Return the currently loaded model name in LM Studio."""
        return await self.lm.get_loaded_model()
