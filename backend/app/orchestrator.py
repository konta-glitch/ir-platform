"""
IR Orchestrator — thin coordinator.

This is the refactored orchestrator.  It does ONE thing: sequence calls to
the service layer in the right order.  No forensic logic lives here.

Pipeline (analyze_structured):
  1. IncidentService.create()         — allocate incident
  2. PipelineService.run()            — detection + sigma + correlation
  3. EscalationService.run_three_pass() — local LLM + cloud if needed
  4. LocalAnalyzer.generate_narrative() — attack narrative
  5. IncidentService.merge_detection_findings() + elevate_severity()
  6. AgentService.save_data()         — store for investigation agent
  7. IncidentService.create()         — persist final incident

Compare to the old orchestrator: each of those steps used to be 30-80
lines embedded directly in analyze_structured.  Now they're one line each.
"""

from __future__ import annotations
import asyncio
import logging
import uuid
from datetime import datetime

from app.config import get_settings
from app.database import get_db
from app.models import (
    AnalyzeRequest,
    Incident,
    IncidentStatus,
    PipelineStats,
)
from app.anonymizer import Anonymizer
from app.local_analyzer import LocalAnalyzer
from app.cloud_escalator import CloudEscalator
from app.detection_engine import DetectionEngine, build_llm_context, ENGINE_VERSION
from app.sigma_engine import SigmaEngine
from app.correlation_engine import CorrelationEngine
from app.structured_logging import PipelineTracer, get_audit_logger
from app.services import AgentService, EscalationService, IncidentService, PipelineService

logger = logging.getLogger(__name__)
audit  = get_audit_logger()


class Orchestrator:
    """
    Thin coordinator — sequences service calls, owns nothing else.
    """

    def __init__(self) -> None:
        db = get_db()

        # Infrastructure
        self.anonymizer = Anonymizer()
        self.local      = LocalAnalyzer()
        self.cloud      = CloudEscalator()

        # Engines (forensic logic)
        self.detection   = DetectionEngine()
        self.sigma       = SigmaEngine()
        self.correlation = CorrelationEngine()

        # Services (domain logic)
        self.incidents  = IncidentService(db)
        self.pipeline   = PipelineService(self.detection, self.sigma, self.correlation)
        self.escalation = EscalationService(self.anonymizer, self.local, self.cloud)
        self.agent      = AgentService(self.local, db)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def analyze_structured(
        self,
        structured_data: dict,
        request: AnalyzeRequest,
        job_id: str | None = None,
    ) -> tuple[Incident, PipelineStats]:
        """
        Main pipeline entry point (collector upload / path-based collection).
        """
        from app.progress import get_tracker
        tracker  = get_tracker()
        incident_id = request.incident_id or str(uuid.uuid4())[:8]
        tracer = PipelineTracer(logger, trace_id=incident_id)
        stats  = PipelineStats()

        total_rows    = sum(len(v) for v in structured_data.values() if isinstance(v, list))
        artifact_types = [k for k in structured_data if not k.startswith("_")]

        audit.record(
            "analysis_started",
            incident_id=incident_id, title=request.title,
            total_rows=total_rows, artifact_count=len(artifact_types),
            artifacts=artifact_types[:30], allow_cloud=request.allow_cloud,
        )

        # ── Step 1: Detection + Sigma + Correlation ────────────────────────────

        def _progress(stage: str, detail: str) -> None:
            if job_id:
                tracker.update(job_id, stage=stage, detail=detail)

        if job_id:
            tracker.update(job_id, stage="detection",
                           detail=f"Scanning {total_rows:,} rows with forensic rules",
                           total_rows=total_rows)

        with tracer.stage("pipeline"):
            pipeline_result = await self.pipeline.run(
                structured_data, job_id=job_id, progress_cb=_progress
            )

        detection_result  = pipeline_result["detection_result"]
        correlation_result = pipeline_result["correlation_result"]

        # Attach correlation summary to behavioral_summary
        detection_result["behavioral_summary"].update({
            "timeline_clusters":         len(correlation_result.get("timeline_clusters", [])),
            "suspicious_process_chains": len(correlation_result.get("suspicious_chains", [])),
            "frequency_outliers":        len(correlation_result.get("frequency_outliers", [])),
        })

        logger.info(
            f"Pipeline complete: {detection_result['total_findings']} findings "
            f"({detection_result['critical_count']} critical, "
            f"{detection_result['high_count']} high)"
        )

        if job_id:
            tracker.update(job_id, detail=f"Found {detection_result['total_findings']} findings",
                           findings_count=detection_result["total_findings"])

        # ── Step 2: LLM analysis (local → cloud) ──────────────────────────────

        if job_id:
            tracker.update(job_id, stage="llm_analysis",
                           detail="Local LLM reasoning over detection findings")

        detection_context = build_llm_context(detection_result)

        with tracer.stage("llm_analysis"):
            analysis, escalation_decision = await self.escalation.run_three_pass(
                detection_data=detection_context,
                context=request.context + (
                    "\n\nThis data was pre-processed by an automated detection engine."
                ),
                data_type=request.data_type.value,
                allow_cloud=request.allow_cloud,
                cloud_threshold=request.cloud_threshold,
            )

        stats.local_analysis_confidence = analysis.overall_confidence
        stats.gaps_found                = escalation_decision.total_gaps_found
        stats.gaps_resolved_locally     = escalation_decision.resolved_locally
        stats.gaps_sent_to_cloud        = escalation_decision.sent_to_cloud
        stats.cloud_used                = escalation_decision.sent_to_cloud > 0

        # ── Step 3: Attack narrative ───────────────────────────────────────────

        if job_id:
            tracker.update(job_id, stage="llm_analysis",
                           detail="LLM building attack narrative")

        with tracer.stage("llm_narrative"):
            narrative = {}
            try:
                narrative = await self.local.generate_narrative(
                    findings=detection_result["findings"],
                    attack_chains=detection_result["behavioral_summary"].get("attack_chains", []),
                    context=request.context,
                )
            except Exception as exc:
                logger.warning(f"Narrative pass failed: {exc}")

        # ── Step 4: Merge findings + severity rollup ───────────────────────────

        analysis = IncidentService.elevate_severity(analysis, detection_result)
        analysis = IncidentService.merge_detection_findings(analysis, detection_result)

        # ── Step 5: Build and persist Incident ────────────────────────────────

        if job_id:
            tracker.update(job_id, stage="report", detail="Building report")

        all_findings = detection_result["findings"]
        incident = Incident(
            id            = incident_id,
            title         = request.title,
            status        = IncidentStatus.TRIAGE,
            severity      = analysis.severity,
            analysis      = analysis,
            escalation    = escalation_decision,
            anonymization_mappings = escalation_decision.anonymization_mappings,
            engine_version = ENGINE_VERSION,
            analyzed_at   = datetime.utcnow().isoformat(),
            raw_artifacts = {
                "detection_summary":          detection_result["behavioral_summary"],
                "detection_findings":         all_findings[:2000],
                "detection_findings_total":   len(all_findings),
                "detection_statistics":       detection_result["statistics"],
                "coverage":                   detection_result.get("coverage", {}),
                "timeline_clusters":          correlation_result.get("timeline_clusters", [])[:20],
                "suspicious_chains":          correlation_result.get("suspicious_chains", [])[:30],
                "frequency_summary":          correlation_result.get("frequency_summary", {}),
                "timeline":                   correlation_result.get("timeline", [])[:200],
                "entity_graph":               correlation_result.get("entity_graph", {"nodes": [], "edges": []}),
                "pipeline_trace":             tracer.summary(),
                "attack_narrative":           narrative,
                "engine_version":             ENGINE_VERSION,
                "analyzed_at":                datetime.utcnow().isoformat(),
            },
        )
        self.incidents.create(incident)

        # ── Step 6: Persist agent data ─────────────────────────────────────────

        agent_blob = {
            "structured_data":  AgentService.cap_structured_data(structured_data),
            "detection_result": detection_result,
            "correlation_result": correlation_result,
        }
        await self.agent.save_data(incident_id, agent_blob)

        audit.record(
            "analysis_completed",
            incident_id=incident_id,
            severity=analysis.severity.value,
            total_findings=detection_result["total_findings"],
            critical=detection_result["critical_count"],
            high=detection_result["high_count"],
            iocs=len(analysis.iocs),
            mitre_techniques=len(analysis.mitre_techniques),
            confidence=round(analysis.overall_confidence, 2),
            cloud_used=stats.cloud_used,
            duration_s=tracer.summary()["total_duration_s"],
            engine_version=ENGINE_VERSION,
        )

        return incident, stats

    async def analyze(
        self, request: AnalyzeRequest
    ) -> tuple[Incident, PipelineStats]:
        """Raw-text analysis (manual paste path)."""
        incident_id = request.incident_id or str(uuid.uuid4())[:8]
        stats = PipelineStats()

        analysis, escalation_decision = await self.escalation.run_three_pass(
            detection_data=request.raw_data,
            context=request.context,
            data_type=request.data_type.value,
            allow_cloud=request.allow_cloud,
            cloud_threshold=request.cloud_threshold,
        )

        stats.local_analysis_confidence = analysis.overall_confidence
        stats.gaps_found                = escalation_decision.total_gaps_found
        stats.gaps_resolved_locally     = escalation_decision.resolved_locally
        stats.gaps_sent_to_cloud        = escalation_decision.sent_to_cloud
        stats.cloud_used                = escalation_decision.sent_to_cloud > 0
        stats.pii_items_redacted        = escalation_decision.pii_redacted

        incident = Incident(
            id            = incident_id,
            title         = request.title,
            status        = IncidentStatus.TRIAGE,
            severity      = analysis.severity,
            analysis      = analysis,
            escalation    = escalation_decision,
            anonymization_mappings = escalation_decision.anonymization_mappings,
            engine_version = ENGINE_VERSION,
            raw_artifacts  = {request.data_type.value: request.raw_data[:5000]},
        )
        self.incidents.create(incident)
        return incident, stats

    # ── Investigation / chat ───────────────────────────────────────────────────

    async def run_investigation(
        self, incident_id: str, max_steps: int = 12,
        question: str = "", progress_cb=None,
    ) -> dict:
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        result = await self.agent.run_investigation(
            incident, max_steps=max_steps, question=question, progress_cb=progress_cb
        )
        incident.raw_artifacts["investigation"] = result
        incident.updated_at = datetime.utcnow()
        self.incidents.update(incident_id)
        return result

    async def ask_agent(
        self, incident_id: str, question: str, progress_cb=None
    ) -> dict:
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        return await self.agent.ask(incident, question, progress_cb=progress_cb)

    def clear_chat(self, incident_id: str) -> None:
        self.agent.clear_chat(incident_id)

    # ── Cloud escalation (manual approval) ────────────────────────────────────

    async def escalate_incident_gaps(self, incident_id: str) -> dict:
        incident = self.incidents.get(incident_id)
        if not incident:
            raise ValueError("Incident not found")
        if not incident.escalation or not incident.escalation.items:
            raise ValueError("No escalation items")
        if not self.cloud.health_check():
            raise ValueError(
                "Claude API key not configured. Add ANTHROPIC_API_KEY to .env and restart."
            )

        unresolved = [
            i for i in incident.escalation.items
            if not i.resolved_by_cloud and not i.resolved_locally
        ]
        if not unresolved:
            return {"message": "All items already resolved", "escalated": 0, "cloud_resolved": 0}

        summary = incident.analysis.summary if incident.analysis else ""
        anon_gaps, anon_summary, mappings = await self.escalation._anonymize_for_cloud(
            unresolved, summary
        )
        enriched_anon = await self.cloud.escalate(items=anon_gaps, incident_summary=anon_summary)
        enriched = self.escalation._deanonymize_gaps(enriched_anon, mappings)

        cloud_resolved = sum(1 for g in enriched if g.resolved_by_cloud)
        incident.escalation.sent_to_cloud  += len(unresolved)
        incident.escalation.cloud_responded += cloud_resolved

        existing = {(m.original, m.anonymized) for m in incident.escalation.anonymization_mappings}
        for m in mappings:
            if (m.original, m.anonymized) not in existing:
                incident.escalation.anonymization_mappings.append(m)
        incident.escalation.pii_redacted = len(incident.escalation.anonymization_mappings)

        if incident.analysis:
            incident.analysis.analyzed_by = "local+cloud"
            for gap in enriched:
                if gap.resolved_by_cloud and gap.cloud_answer:
                    incident.analysis.cloud_enrichments.append(
                        f"[Cloud] {gap.question}: {gap.cloud_answer}"
                    )
        self.incidents.update(incident_id)

        return {
            "escalated":      len(unresolved),
            "cloud_resolved": cloud_resolved,
            "pii_redacted":   len(mappings),
            "enrichments": [
                {"question": g.question, "answer": g.cloud_answer}
                for g in enriched if g.cloud_answer
            ],
        }

    # ── Incident CRUD (thin pass-through) ─────────────────────────────────────

    def get_incident(self, incident_id: str) -> Incident | None:
        return self.incidents.get(incident_id)

    def list_incidents(self) -> list[Incident]:
        return self.incidents.list_all()

    def update_incident(self, incident_id: str, **kwargs) -> Incident | None:
        return self.incidents.update(incident_id, **kwargs)

    def delete_incident(self, incident_id: str) -> bool:
        self.agent.evict(incident_id)
        return self.incidents.delete(incident_id)

    def deanonymize_report(self, incident_id: str) -> dict | None:
        incident = self.incidents.get(incident_id)
        if not incident or not incident.analysis:
            return None
        return {
            "incident_id": incident_id,
            "deanonymized_summary": self.anonymizer.deanonymize(
                incident.analysis.summary, incident.anonymization_mappings
            ),
            "deanonymized_enrichments": [
                self.anonymizer.deanonymize(e, incident.anonymization_mappings)
                for e in incident.analysis.cloud_enrichments
            ],
            "mappings": [m.model_dump() for m in incident.anonymization_mappings],
        }
