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
from app.detection_engine import _cluster_findings_by_folder
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
- DUAL-USE TOOLS (AnyDesk, TeamViewer, ScreenConnect, PsExec, and other legitimate
  remote-access/admin software) are NOT inherently malicious — they are routinely
  deployed by IT departments and MSPs. The mere PRESENCE of such a tool is NOT
  sufficient grounds for malicious:true. Only set malicious:true on a dual-use
  tool when the evidence corroborates misuse — e.g. unusual install location,
  install time clustered with other suspicious activity, connection to a known-bad
  IP, or absence of any legitimate business justification in the context provided.
  Without that corroboration, set malicious:false and confidence below 0.5, with
  confidence_reason noting it requires verification against IT asset records.
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
                                  context: str = "",
                                  batch_size: int = 0) -> dict:
        """
        Second LLM pass: generate an attack narrative + per-finding triage.

        Batches are processed CONCURRENTLY (asyncio) against the local LLM,
        bounded by settings.narrative_concurrency, so wall-clock time scales
        down roughly with the concurrency level instead of being the sum of
        all batches. Batch ORDER is preserved in the merged result so the
        narrative reads in sequence regardless of completion order.

        Severity scope is configurable via settings.narrative_severities and
        defaults to ALL severities — this is an IR tool, so nothing is dropped
        from the narrative. (Set it to "critical,high" only if you explicitly
        want to trade coverage for speed.)
        """
        if not findings:
            return {}

        from app.config import get_settings
        import asyncio

        settings = get_settings()
        if not batch_size:
            batch_size = settings.narrative_batch_size
        concurrency = max(1, settings.narrative_concurrency)

        # Severity scope — defaults to every severity (full coverage).
        allowed = {
            s.strip().lower()
            for s in str(settings.narrative_severities).split(",")
            if s.strip()
        }
        narrative_findings = [
            f for f in findings
            if not allowed or str(f.get("severity", "")).lower() in allowed
        ]
        if not narrative_findings:
            narrative_findings = findings

        logger.info(
            f"Narrative pass: {len(narrative_findings)} findings selected "
            f"(severities: {','.join(sorted(allowed)) or 'all'}) from {len(findings)} total"
        )

        # Cluster over the FULL finding set BEFORE batching so cross-batch
        # clusters are still detected correctly.
        all_clusters = _cluster_findings_by_folder(findings)
        if all_clusters:
            logger.info(
                f"Narrative pass: {len(all_clusters)} same-folder cluster(s) detected "
                f"(e.g. multi-file tool installs) — will be flagged to the LLM per batch"
            )

        batches = [narrative_findings[i:i + batch_size]
                   for i in range(0, len(narrative_findings), batch_size)]
        logger.info(
            f"Narrative pass: {len(narrative_findings)} findings in {len(batches)} batch(es) "
            f"of up to {batch_size}, concurrency={concurrency}"
        )

        sem = asyncio.Semaphore(concurrency)

        async def run_batch(batch_num: int, batch: list[dict]):
            batch_ids = {f["id"] for f in batch}
            # Only pass clusters that have at least one member in THIS batch —
            # a cluster split across batches still gets mentioned in each
            # relevant batch, so the LLM sees the connection no matter which
            # batch happens to contain which member.
            relevant_clusters = [
                c for c in all_clusters if batch_ids & set(c["finding_ids"])
            ]
            async with sem:
                return await self._generate_narrative_batch(
                    batch, attack_chains, context,
                    batch_num=batch_num, total_batches=len(batches),
                    clusters=relevant_clusters,
                )

        # Launch all batches; gather preserves input order, so batch_results
        # stays in narrative sequence even though they finish out of order.
        tasks = [run_batch(i, b) for i, b in enumerate(batches, start=1)]
        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        batch_results = []
        for i, res in enumerate(gathered, start=1):
            if isinstance(res, Exception):
                logger.error(f"Narrative batch {i} failed: {res}")
                continue
            if res:
                batch_results.append(res)

        if not batch_results:
            return {}
        if len(batch_results) == 1:
            return batch_results[0]
        return self._merge_narrative_batches(batch_results)

    async def _generate_narrative_batch(
        self, findings: list[dict], attack_chains: list[str], context: str,
        batch_num: int = 1, total_batches: int = 1,
        clusters: list[dict] | None = None,
    ) -> dict:
        """Run one narrative pass over a single batch of findings."""
        finding_lines = []
        for f in findings:
            ev = f.get("evidence", {})
            locator = ev.get("locator", f.get("artifact", ""))
            finding_lines.append(
                f"[{f['id']}] {f['severity'].upper()} {f['title']} "
                f"(MITRE {f.get('mitre', 'N/A')}) — {f['description'][:150]} "
                f"[evidence: {locator}]"
            )
        findings_text = "\n".join(finding_lines)
        chains_text = "\n".join(f"- {c}" for c in attack_chains) or "None detected"

        # Same-folder clusters — e.g. 4 separate "rare executable" findings
        # that are actually 4 binaries from one installed tool. Without this,
        # the narrative pass sees them as N isolated low-confidence items
        # (confirmed: this was exactly how a JWrapper remote-access install,
        # spread across 4 findings, got described as generic noise instead
        # of one coherent tool installation).
        cluster_text = ""
        if clusters:
            cluster_lines = [
                f"  • {c['count']}× findings share folder '{c['folder']}': "
                + ", ".join(f"[{i}]" for i in c["finding_ids"])
                for c in clusters
            ]
            cluster_text = (
                "\n\nIMPORTANT — these findings share a parent folder and very "
                "likely represent ONE installed tool or staging event, not "
                "independent occurrences. Treat each group as a single entity "
                "in your narrative, not as separate low-confidence items:\n"
                + "\n".join(cluster_lines)
            )

        batch_note = (
            f"\nNOTE: This is batch {batch_num} of {total_batches} covering a subset "
            f"of all findings in this incident — other batches cover the rest. Write "
            f"your narrative for THIS batch's findings only; do not assume these are "
            f"the only findings in the incident."
            if total_batches > 1 else ""
        )

        system = f"""You are a senior incident responder writing the analysis section of an IR report.
You are RIGOROUS about false positives — automated detections are leads, not conclusions.
{batch_note}

Given automated detection findings, produce a JSON object with:
{{
  "attack_narrative": "2-4 paragraph plain-language story of what likely happened, in logical order, referencing finding IDs like [F0001]. If the evidence is weak or ambiguous, SAY SO rather than inventing an attack.",
  "key_findings": [{{"finding_id": "F0001", "why_it_matters": "1-2 sentences", "recommended_action": "specific action", "assessment": "true_positive | likely_benign | needs_review"}}],
  "likely_false_positives": [{{"finding_id": "F0002", "reason": "why this is probably benign"}}],
  "threat_assessment": "1 paragraph: severity, attacker sophistication, likely objective — calibrated to the ACTUAL evidence strength",
  "confidence": 0.0-1.0
}}

Critical guidance to avoid false positives:
- Many Sigma matches are low-fidelity (a tool CAN be misused, not that it WAS). Weigh them lightly unless corroborated.
- A single finding type repeated many times (high occurrence count) is often noise or normal system behavior, not N separate attacks.
- Distinguish "an attacker did X" from "X is technically possible here". Only claim compromise when evidence corroborates across artifacts (e.g. process tree + network + log clearing together).
- If findings are mostly isolated medium-severity Sigma hits with no corroboration, the honest verdict is "suspicious indicators requiring review", NOT "active compromise".
- PERSISTENCE MECHANISMS (services, scheduled tasks, autorun/registry Run keys) deserve
  extra scrutiny regardless of the heuristic severity label — a "low" severity service
  binary in a suspicious path can be just as significant as a "high" severity one-off
  command, because persistence is how an attacker survives a reboot. Don't let the
  severity label alone determine how much attention a finding gets in your narrative.
- Reference finding IDs in brackets. Technical but readable. Output ONLY valid JSON."""

        user = f"""Analyst context: {context}

Detected attack chains:
{chains_text}
{cluster_text}

Findings{f' (batch {batch_num}/{total_batches})' if total_batches > 1 else ''}:
{findings_text}

Write the IR analysis as JSON. Be rigorous: separate corroborated true positives from
isolated low-confidence hits, and calibrate your confidence to the actual evidence."""

        try:
            logger.info(
                f"Narrative pass batch {batch_num}/{total_batches}: "
                f"analyzing {len(findings)} findings via LLM"
            )
            raw = await self._call_llm(system, user, temperature=0.2, max_tokens=2500)
            result = self._parse_json(raw)
            if result:
                logger.info(f"Narrative pass batch {batch_num}/{total_batches}: generated narrative")
            return result
        except Exception as e:
            logger.warning(f"Narrative generation failed for batch {batch_num}/{total_batches}: {e}")
            return {}

    @staticmethod
    def _merge_narrative_batches(batch_results: list[dict]) -> dict:
        """
        Merge multiple per-batch narratives into one coherent result.

        Narratives are concatenated with batch separators (each batch saw a
        different slice of findings, so its narrative is only valid for that
        slice — presenting them as distinct sections is more honest than
        trying to algorithmically blend prose written by separate LLM calls).
        key_findings and likely_false_positives are simple list unions since
        finding_ids are unique across batches. Confidence is averaged.
        """
        narratives = [r.get("attack_narrative", "") for r in batch_results if r.get("attack_narrative")]
        merged_narrative = "\n\n---\n\n".join(
            f"[Findings batch {i+1}]\n{n}" for i, n in enumerate(narratives)
        )

        key_findings = []
        false_positives = []
        threat_assessments = []
        confidences = []
        for r in batch_results:
            key_findings.extend(r.get("key_findings", []))
            false_positives.extend(r.get("likely_false_positives", []))
            if r.get("threat_assessment"):
                threat_assessments.append(r["threat_assessment"])
            if isinstance(r.get("confidence"), (int, float)):
                confidences.append(r["confidence"])

        return {
            "attack_narrative": merged_narrative,
            "key_findings": key_findings,
            "likely_false_positives": false_positives,
            "threat_assessment": " ".join(threat_assessments),
            "confidence": sum(confidences) / len(confidences) if confidences else 0.5,
            "batched": True,
            "batch_count": len(batch_results),
        }

    def _parse_json(self, text: str) -> dict:
        """Safely parse JSON from LLM output."""
        cleaned = text.strip()

        # Reasoning models (DeepSeek-R1, QwQ, etc.) emit a <think>...</think>
        # chain-of-thought block BEFORE the actual answer. That block is prose,
        # often containing stray '{' '}' characters, so it both (a) makes the
        # response not start with JSON and (b) confuses a greedy { ... } regex
        # into grabbing the wrong span. Strip it before doing anything else.
        # Handles a closed block, and the degenerate case where the model only
        # opened <think> and we keep everything after it.
        if "<think>" in cleaned:
            if "</think>" in cleaned:
                cleaned = cleaned.split("</think>", 1)[1].strip()
            else:
                cleaned = cleaned.split("<think>", 1)[1].strip()

        # Strip ```json fences if present.
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError as e:
            logger.warning(f"JSON parse failed: {e}")
            # Prefer a brace-balanced extraction over a greedy regex: scan for
            # the first '{' and walk to its matching '}', respecting strings
            # and escapes. This survives reasoning text or trailing prose that
            # contains unbalanced braces, which the old r'\{[\s\S]*\}' caught
            # wrongly (it grabbed from the first '{' to the LAST '}' anywhere).
            candidate = self._extract_balanced_json(cleaned)
            if candidate is None:
                match = re.search(r'\{[\s\S]*\}', cleaned)
                candidate = match.group() if match else None
            if candidate:
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError as e2:
                    # Smaller/weaker local models sometimes emit a raw
                    # newline/tab/control character inside a JSON string
                    # value instead of properly escaping it (e.g. a literal
                    # line break in the middle of "attack_narrative": "..."
                    # text) — valid per how the model "meant" it, but
                    # invalid per the JSON spec, which json.loads() (and
                    # Python's json.JSONDecodeError "Invalid control
                    # character" message) correctly rejects. Escaping
                    # control characters that appear strictly INSIDE a
                    # quoted string (not the structural whitespace between
                    # JSON tokens) recovers these without silently
                    # corrupting otherwise-valid JSON.
                    if "control character" in str(e2).lower():
                        sanitized = self._escape_control_chars_in_strings(candidate)
                        try:
                            result = json.loads(sanitized)
                            logger.info("JSON recovered after escaping control characters in string values")
                            return result
                        except json.JSONDecodeError:
                            pass
            return {}

    @staticmethod
    def _extract_balanced_json(text: str) -> str | None:
        """
        Return the first brace-balanced {...} span that actually parses as
        JSON, or None.

        Reasoning text before the real answer can contain balanced-but-junk
        braces like '{stray}'. So we don't just return the first balanced
        span — we try each candidate (scanning successive '{' positions) and
        return the first one json.loads() accepts. This skips prose braces and
        lands on the real object.
        """
        search_from = 0
        while True:
            start = text.find("{", search_from)
            if start == -1:
                return None
            depth = 0
            in_string = False
            escape_next = False
            end = -1
            for i in range(start, len(text)):
                ch = text[i]
                if escape_next:
                    escape_next = False
                    continue
                if ch == "\\":
                    escape_next = True
                    continue
                if ch == '"':
                    in_string = not in_string
                    continue
                if in_string:
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        end = i
                        break
            if end != -1:
                candidate = text[start:end + 1]
                try:
                    json.loads(candidate)
                    return candidate  # parses cleanly — this is the one
                except json.JSONDecodeError:
                    pass  # balanced but not valid JSON (e.g. '{stray}') — keep looking
            # Advance past this '{' and try the next candidate.
            search_from = start + 1

    @staticmethod
    def _escape_control_chars_in_strings(text: str) -> str:
        """
        Walk the text and escape raw control characters (newline, tab,
        carriage return) ONLY when inside a JSON string (between unescaped
        double quotes) — leaves structural JSON whitespace alone so
        indentation/formatting between tokens isn't disturbed.
        """
        out = []
        in_string = False
        escape_next = False
        for ch in text:
            if escape_next:
                out.append(ch)
                escape_next = False
                continue
            if ch == "\\":
                out.append(ch)
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                out.append(ch)
                continue
            if in_string and ch == "\n":
                out.append("\\n")
                continue
            if in_string and ch == "\t":
                out.append("\\t")
                continue
            if in_string and ch == "\r":
                out.append("\\r")
                continue
            out.append(ch)
        return "".join(out)

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