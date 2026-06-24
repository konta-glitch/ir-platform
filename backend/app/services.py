"""
Services layer — one class per domain, one responsibility per class.

These services replace the fat methods that lived directly on Orchestrator.
The orchestrator now delegates to these and stays "thin" — it coordinates
but never implements.

Service catalogue:
  - IncidentService   : CRUD for Incident, persistence, severity rollup
  - PipelineService   : orchestrates the detection → sigma → correlation chain
  - EscalationService : local → cloud escalation with anonymisation
  - ReportService     : report generation (delegates to report_generator)
  - AgentService      : investigation agent lifecycle
"""

from __future__ import annotations
import asyncio
import copy
import logging
import uuid
from datetime import datetime
from typing import Any, Callable

from app.models import (
    AnalysisResult,
    Artifact,
    EscalationDecision,
    EscalationItem,
    Incident,
    IncidentStatus,
    IOC,
    MITRETechnique,
    PipelineStats,
    Severity,
)

logger = logging.getLogger(__name__)


# ── IncidentService ────────────────────────────────────────────────────────────

class IncidentService:
    """
    All incident lifecycle operations: create, read, update, delete.
    Owns the in-memory cache and write-through to the database.
    """

    def __init__(self, db):
        self._db = db
        self._incidents: dict[str, Incident] = {}
        self._load_from_db()

    # ── Persistence ──

    def _load_from_db(self) -> None:
        try:
            for data in self._db.list_incidents():
                try:
                    inc = Incident(**data)
                    self._incidents[inc.id] = inc
                except Exception as exc:
                    logger.warning(f"Could not rehydrate incident {data.get('id')}: {exc}")
            if self._incidents:
                logger.info(f"Loaded {len(self._incidents)} incidents from database")
        except Exception as exc:
            logger.warning(f"Could not load incidents from DB: {exc}")

    def _persist(self, incident: Incident) -> None:
        try:
            self._db.save_incident(
                incident_id = incident.id,
                incident_json = incident.model_dump(),
                title = incident.title,
                status = incident.status.value,
                severity = incident.severity.value,
                created_at = incident.created_at.isoformat(),
                updated_at = incident.updated_at.isoformat(),
            )
        except Exception as exc:
            logger.error(f"Failed to persist incident {incident.id}: {exc}")

    # ── CRUD ──

    def create(self, incident: Incident) -> Incident:
        if not incident.id:
            incident.id = str(uuid.uuid4())[:8]
        self._incidents[incident.id] = incident
        self._persist(incident)
        return incident

    def get(self, incident_id: str) -> Incident | None:
        return self._incidents.get(incident_id)

    def list_all(self) -> list[Incident]:
        return list(self._incidents.values())

    def update(self, incident_id: str, **kwargs) -> Incident | None:
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        for key, value in kwargs.items():
            if hasattr(incident, key) and value is not None:
                setattr(incident, key, value)
        incident.updated_at = datetime.utcnow()
        self._persist(incident)
        return incident

    def delete(self, incident_id: str) -> bool:
        existed = incident_id in self._incidents
        self._incidents.pop(incident_id, None)
        try:
            self._db.delete_incident(incident_id)
        except Exception as exc:
            logger.warning(f"Could not delete incident from DB: {exc}")
        return existed

    def count(self) -> int:
        try:
            return self._db.count_incidents()
        except Exception:
            return len(self._incidents)

    # ── Severity rollup ──

    @staticmethod
    def elevate_severity(analysis: AnalysisResult, detection_result: dict) -> AnalysisResult:
        """
        Bump severity based on detection engine findings.
        Keeps this logic in one place instead of scattered across orchestrator.
        """
        if detection_result["critical_count"] > 0:
            analysis.severity = Severity.CRITICAL
        elif detection_result["high_count"] >= 3:
            analysis.severity = Severity.HIGH
        elif detection_result["high_count"] > 0 and analysis.severity in (Severity.LOW, Severity.INFO):
            analysis.severity = Severity.MEDIUM
        return analysis

    # ── Finding merge ──

    @staticmethod
    def merge_detection_findings(analysis: AnalysisResult,
                                  detection_result: dict) -> AnalysisResult:
        """Merge high-confidence engine findings into the LLM analysis."""
        existing_values = {ioc.value for ioc in analysis.iocs}
        mitre_seen = {t.technique_id for t in analysis.mitre_techniques}

        for finding in detection_result["findings"]:
            if finding["severity"] in ("critical", "high"):
                ev = finding["evidence"]
                ioc_value = (ev.get("path") or ev.get("cmdline") or ev.get("remote")
                             or ev.get("name") or ev.get("value") or finding["title"])
                if ioc_value and ioc_value not in existing_values:
                    analysis.iocs.append(IOC(
                        type=finding["category"],
                        value=str(ioc_value)[:200],
                        context=f"[{finding['id']}] {finding['description'][:200]}",
                        confidence=0.85 if finding["severity"] == "critical" else 0.7,
                        malicious=finding["severity"] == "critical",
                        confidence_reason=f"Detection engine: {finding['title']}",
                    ))
                    existing_values.add(ioc_value)

                if finding["mitre"] and finding["mitre"] not in mitre_seen:
                    analysis.mitre_techniques.append(MITRETechnique(
                        technique_id=finding["mitre"],
                        technique_name=finding["title"],
                        tactic=finding["category"],
                        confidence=0.8,
                        evidence=f"[{finding['id']}] {finding['description'][:200]}",
                    ))
                    mitre_seen.add(finding["mitre"])

        return analysis


# ── PipelineService ────────────────────────────────────────────────────────────

class PipelineService:
    """
    Runs the detection → sigma → correlation pipeline.

    Coordinates DetectionEngine, SigmaEngine, and CorrelationEngine in the
    right order, with dedup and allowlist applied.  Returns structured results
    the orchestrator can hand to the LLM layer.
    """

    def __init__(self, detection_engine, sigma_engine, correlation_engine):
        self._detection  = detection_engine
        self._sigma      = sigma_engine
        self._correlation = correlation_engine

    async def run(
        self,
        structured_data: dict,
        job_id: str | None = None,
        progress_cb: Callable | None = None,
    ) -> dict:
        """
        Full pipeline run.  Returns a dict with:
          - detection_result
          - correlation_result
          - total_findings, critical_count, high_count, medium_count
        """
        from app.correlation_engine import apply_allowlist

        # 1. Detection engine
        def _det_progress(artifact, processed, total):
            if progress_cb:
                progress_cb("detection", f"Scanning {artifact}: {processed:,}/{total:,}")

        detection_result = await asyncio.to_thread(
            self._detection.analyze, structured_data, _det_progress
        )

        # 2. Sigma rules
        def _sigma_progress(artifact, n_rules, n_rows):
            if progress_cb:
                progress_cb("sigma", f"Sigma: {artifact} ({n_rules} rules × {n_rows:,} rows)")

        sigma_findings = await asyncio.to_thread(
            self._sigma.analyze, structured_data, 20, _sigma_progress
        )

        if sigma_findings:
            sigma_deduped = self._dedupe_sigma(sigma_findings)
            for sf in sigma_deduped:
                sf["id"] = (
                    f"S{len([f for f in detection_result['findings'] if f['id'].startswith('S')]) + 1:04d}"
                )
                detection_result["findings"].append(sf)
            detection_result["sigma_findings_count"] = len(sigma_deduped)
            detection_result["sigma_raw_matches"]    = len(sigma_findings)
            logger.info(f"Sigma: {len(sigma_findings)} raw → {len(sigma_deduped)} unique rules")

        # 3. Correlation engine
        correlation_result = await asyncio.to_thread(
            self._correlation.correlate,
            structured_data,
            detection_result["findings"],
        )
        corr_findings = correlation_result.get("new_findings", [])
        if corr_findings:
            detection_result["findings"].extend(corr_findings)

        # 4. Allowlist suppression
        detection_result["findings"], suppressed = apply_allowlist(detection_result["findings"])
        if suppressed:
            logger.info(f"Allowlist suppressed {suppressed} known-good findings")

        # 5. Recompute counts and sort
        self._recount(detection_result)
        detection_result["behavioral_summary"]["allowlist_suppressed"] = suppressed

        return {
            "detection_result":  detection_result,
            "correlation_result": correlation_result,
        }

    # ── Helpers ──

    @staticmethod
    def _dedupe_sigma(sigma_findings: list) -> list:
        """Collapse Sigma matches by (rule title, artifact) — one entry per rule."""
        seen: dict = {}
        deduped = []
        for sf in sigma_findings:
            key = (sf.get("title", ""), sf.get("artifact", ""))
            if key in seen:
                first = seen[key]
                first["occurrences"] = first.get("occurrences", 1) + 1
                locs = first.setdefault("occurrence_locators", [])
                loc = (sf.get("evidence", {}).get("locator") or
                       f"{sf.get('artifact')} (row {sf.get('evidence', {}).get('row_index')})")
                if loc and len(locs) < 10:
                    locs.append(loc)
            else:
                sf["occurrences"] = 1
                seen[key] = sf
                deduped.append(sf)
        return deduped

    @staticmethod
    def _recount(detection_result: dict) -> None:
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        detection_result["findings"].sort(
            key=lambda f: (sev_order.get(f["severity"], 5), -f.get("score", 0))
        )
        detection_result["total_findings"]  = len(detection_result["findings"])
        detection_result["critical_count"]  = sum(1 for f in detection_result["findings"] if f["severity"] == "critical")
        detection_result["high_count"]      = sum(1 for f in detection_result["findings"] if f["severity"] == "high")
        detection_result["medium_count"]    = sum(1 for f in detection_result["findings"] if f["severity"] == "medium")


# ── EscalationService ─────────────────────────────────────────────────────────

class EscalationService:
    """
    Handles the local → cloud escalation flow, including anonymisation
    at the cloud boundary and de-anonymisation on return.

    Nothing about *how* to anonymise or *how* to call the cloud lives here —
    those are injected dependencies.
    """

    def __init__(self, anonymizer, local_analyzer, cloud_escalator):
        self._anon  = anonymizer
        self._local = local_analyzer
        self._cloud = cloud_escalator

    async def run_three_pass(
        self,
        detection_data: str,
        context: str,
        data_type: str,
        allow_cloud: bool,
        cloud_threshold: float,
    ) -> tuple[AnalysisResult, EscalationDecision]:
        """Three-pass: local → focused local → cloud (if needed)."""

        # Pass 1
        logger.info("Pass 1: primary local analysis")
        analysis, gaps = await self._local.analyze(
            anonymized_data=detection_data,
            context=context,
            data_type=data_type,
        )
        escalation = EscalationDecision(total_gaps_found=len(gaps))

        if not gaps:
            analysis.analyzed_by = "local"
            escalation.escalation_reason = "No knowledge gaps identified"
            return analysis, escalation

        # Pass 2
        logger.info(f"Pass 2: trying to resolve {len(gaps)} gaps locally")
        remaining_gaps = await self._local.try_answer_gaps(gaps, analysis.summary)
        escalation.resolved_locally = len(gaps) - len(remaining_gaps)

        if not remaining_gaps:
            analysis.analyzed_by = "local"
            escalation.escalation_reason = "All gaps resolved locally"
            for gap in gaps:
                if gap.resolved_locally and gap.local_answer:
                    analysis.cloud_enrichments.append(f"[Local] {gap.question}: {gap.local_answer}")
            return analysis, escalation

        # Pass 3 — cloud
        if not allow_cloud:
            analysis.analyzed_by = "local"
            escalation.escalation_reason = f"Cloud disabled. {len(remaining_gaps)} gaps unresolved."
            escalation.items = remaining_gaps
            return analysis, escalation

        high_priority = any(g.priority == "high" for g in remaining_gaps)
        if analysis.overall_confidence >= cloud_threshold and not high_priority:
            analysis.analyzed_by = "local"
            escalation.escalation_reason = (
                f"Confidence {analysis.overall_confidence:.0%} >= threshold. Skipping cloud."
            )
            escalation.items = remaining_gaps
            return analysis, escalation

        logger.info(f"Pass 3: escalating {len(remaining_gaps)} gaps to cloud (anonymising first)")
        escalation.sent_to_cloud = len(remaining_gaps)

        anon_gaps, summary_anon, mappings = await self._anonymize_for_cloud(
            remaining_gaps, analysis.summary
        )
        escalation.anonymization_mappings = mappings
        escalation.pii_redacted = len(mappings)

        enriched_anon = await self._cloud.escalate(
            items=anon_gaps, incident_summary=summary_anon
        )
        enriched_gaps = self._deanonymize_gaps(enriched_anon, mappings)

        cloud_resolved = sum(1 for g in enriched_gaps if g.resolved_by_cloud)
        escalation.cloud_responded = cloud_resolved
        escalation.items = enriched_gaps
        escalation.escalation_reason = f"Cloud resolved {cloud_resolved}/{len(remaining_gaps)} gaps."

        analysis.analyzed_by = "local+cloud"
        for gap in enriched_gaps:
            if gap.resolved_by_cloud and gap.cloud_answer:
                analysis.cloud_enrichments.append(f"[Cloud] {gap.question}: {gap.cloud_answer}")

        return analysis, escalation

    async def _anonymize_for_cloud(
        self, gaps: list[EscalationItem], summary: str
    ) -> tuple[list[EscalationItem], str, list]:
        SEP = "\n\u241e\n"
        parts = [summary or ""] + [s for g in gaps for s in (g.question or "", g.context or "")]
        combined = SEP.join(parts)

        anon = await self._anon.anonymize(combined)
        chunks = anon.anonymized_text.split(SEP)

        anon_summary = chunks[0] if chunks else (summary or "")
        anon_gaps, idx = [], 1
        for g in gaps:
            ng = copy.copy(g)
            ng.question = chunks[idx]     if idx < len(chunks)     else g.question
            ng.context  = chunks[idx + 1] if idx + 1 < len(chunks) else g.context
            idx += 2
            anon_gaps.append(ng)

        return anon_gaps, anon_summary, anon.mappings

    def _deanonymize_gaps(
        self, gaps: list[EscalationItem], mappings: list
    ) -> list[EscalationItem]:
        if not mappings:
            return gaps
        for g in gaps:
            if g.cloud_answer:
                g.cloud_answer = self._anon.deanonymize(g.cloud_answer, mappings)
            if g.question:
                g.question = self._anon.deanonymize(g.question, mappings)
            if g.context:
                g.context = self._anon.deanonymize(g.context, mappings)
        return gaps


# ── AgentService ───────────────────────────────────────────────────────────────

class AgentService:
    """
    Manages the investigation agent: in-memory data cache, conversation
    history, and delegation to InvestigationAgent.
    """

    def __init__(self, local_analyzer, db):
        self._local     = local_analyzer
        self._db        = db
        self._data:    dict[str, dict] = {}   # incident_id → agent blob
        self._history: dict[str, list] = {}   # incident_id → chat history

    # ── Data lifecycle ──

    async def save_data(self, incident_id: str, blob: dict) -> None:
        self._data[incident_id] = blob
        try:
            await asyncio.to_thread(self._db.save_agent_data, incident_id, blob)
        except Exception as exc:
            logger.warning(f"Could not persist agent data for {incident_id}: {exc}")

    async def load_data(self, incident_id: str) -> dict | None:
        if incident_id in self._data:
            return self._data[incident_id]
        data = await asyncio.to_thread(self._db.get_agent_data, incident_id)
        if data:
            self._data[incident_id] = data
        return data

    def clear_chat(self, incident_id: str) -> None:
        self._history.pop(incident_id, None)

    def evict(self, incident_id: str) -> None:
        self._data.pop(incident_id, None)
        self._history.pop(incident_id, None)

    @staticmethod
    def cap_structured_data(structured_data: dict, max_rows: int = 5000) -> dict:
        """Bound agent data to avoid unbounded storage on huge collections."""
        capped: dict = {}
        truncation: dict = {}
        for key, value in structured_data.items():
            if isinstance(value, list) and len(value) > max_rows:
                capped[key] = value[:max_rows]
                truncation[key] = {"kept": max_rows, "total": len(value)}
            else:
                capped[key] = value
        if truncation:
            capped["_agent_truncation"] = truncation
        return capped

    # ── Investigation ──

    async def run_investigation(
        self,
        incident: Incident,
        max_steps: int = 12,
        question: str = "",
        progress_cb: Callable | None = None,
    ) -> dict:
        from app.investigation_agent import InvestigationAgent, InvestigationTools
        from app.detection_engine import build_llm_context

        agent_data = await self.load_data(incident.id)
        if not agent_data:
            raise ValueError("Investigation data not found. Re-run the analysis.")

        tools = InvestigationTools(
            agent_data["structured_data"],
            agent_data["detection_result"],
            agent_data["correlation_result"],
        )
        case_summary = build_llm_context(agent_data["detection_result"])
        if question:
            case_summary += f"\n\nThe analyst specifically wants you to investigate: {question}"

        agent = InvestigationAgent(self._local.chat_messages, tools)
        result = await agent.investigate(case_summary, max_steps=max_steps, progress_cb=progress_cb)
        return result

    async def ask(
        self,
        incident: Incident,
        question: str,
        progress_cb: Callable | None = None,
    ) -> dict:
        from app.investigation_agent import InvestigationAgent, InvestigationTools
        from app.detection_engine import build_llm_context

        agent_data = await self.load_data(incident.id)
        if not agent_data:
            raise ValueError(
                "Investigation data not found. Re-run the analysis to chat with the agent."
            )

        tools = InvestigationTools(
            agent_data["structured_data"],
            agent_data["detection_result"],
            agent_data["correlation_result"],
        )
        agent = InvestigationAgent(self._local.chat_messages, tools)

        history = self._history.get(incident.id)
        case_summary = "" if history else build_llm_context(agent_data["detection_result"])

        result = await agent.ask(
            question, history=history, case_summary=case_summary, progress_cb=progress_cb
        )
        self._history[incident.id] = result["history"]
        return {"answer": result["answer"], "steps": result["steps"]}
