"""
Domain models for the IR Platform.

Key additions vs original:
  - Artifact: unified model for all forensic artifacts (replaces raw dicts)
  - ArtifactType: typed enum replacing string literals scattered across code
  - Incident.engine_version: audit trail — which engine version produced findings
  - All enums centralised here to avoid circular imports
"""

from __future__ import annotations
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
from typing import Any


# ── Enums ──────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class IncidentStatus(str, Enum):
    NEW           = "new"
    TRIAGE        = "triage"
    INVESTIGATING = "investigating"
    CONTAINMENT   = "containment"
    ERADICATION   = "eradication"
    RECOVERY      = "recovery"
    CLOSED        = "closed"


class DataType(str, Enum):
    PROCESSES  = "processes"
    NETWORK    = "network"
    FILESYSTEM = "filesystem"
    EVENTLOG   = "eventlog"
    PERSISTENCE = "persistence"
    USERS      = "users"
    SOFTWARE   = "software"
    MIXED      = "mixed"


class ArtifactType(str, Enum):
    """Canonical artifact types emitted by all parsers/plugins."""
    PROCESS    = "process"
    NETWORK    = "network"
    FILE       = "file"
    REGISTRY   = "registry"
    SERVICE    = "service"
    TASK       = "task"
    USER       = "user"
    EVENT      = "event"
    PREFETCH   = "prefetch"
    MFT        = "mft"
    BROWSER    = "browser"
    UNKNOWN    = "unknown"


# ── Unified Artifact model ─────────────────────────────────────────────────────

class Artifact(BaseModel):
    """
    Normalised forensic artifact — the single data format every plugin produces
    and every detection/correlation rule consumes.

    This is the core of the plugin system: parsers (EVTX, MFT, Prefetch, …)
    convert raw data into Artifact objects.  Detection and correlation engines
    work exclusively on Artifacts, so new parsers need zero changes to the
    engine layer.
    """
    id:         str = ""
    type:       ArtifactType = ArtifactType.UNKNOWN
    source:     str  = ""          # which collector/plugin produced this
    timestamp:  str  = ""          # ISO-8601 or empty
    host:       str  = ""
    attributes: dict[str, Any] = {}  # type-specific payload

    # Lineage / audit
    collector_version: str = ""
    parsed_at:         str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ── Anonymisation ──────────────────────────────────────────────────────────────

class AnonymizationMapping(BaseModel):
    original:   str
    anonymized: str
    category:   str


class AnonymizationResult(BaseModel):
    original_text:   str
    anonymized_text: str
    mappings:        list[AnonymizationMapping] = []
    model_used:      str = ""


# ── Escalation (local → cloud) ────────────────────────────────────────────────

class EscalationItem(BaseModel):
    question:          str
    category:          str  = "general"
    context:           str  = ""
    priority:          str  = "medium"
    local_answer:      str  = ""
    resolved_locally:  bool = False
    cloud_answer:      str  = ""
    resolved_by_cloud: bool = False


class EscalationDecision(BaseModel):
    total_gaps_found:       int  = 0
    resolved_locally:       int  = 0
    sent_to_cloud:          int  = 0
    cloud_responded:        int  = 0
    escalation_reason:      str  = ""
    items:                  list[EscalationItem]         = []
    anonymization_mappings: list[AnonymizationMapping]   = []
    pii_redacted:           int  = 0


# ── Analysis ──────────────────────────────────────────────────────────────────

class IOC(BaseModel):
    type:              str
    value:             str
    context:           str   = ""
    confidence:        float = Field(ge=0, le=1, default=0.5)
    malicious:         bool  = False
    confidence_reason: str   = ""


class MITRETechnique(BaseModel):
    technique_id:   str
    technique_name: str
    tactic:         str
    confidence:     float = Field(ge=0, le=1, default=0.5)
    evidence:       str   = ""


class TimelineEntry(BaseModel):
    timestamp:    str
    event:        str
    source:       str = ""
    significance: str = ""


class AnalysisResult(BaseModel):
    summary:               str
    severity:              Severity
    iocs:                  list[IOC]             = []
    mitre_techniques:      list[MITRETechnique]  = []
    recommendations:       list[str]             = []
    timeline:              list[TimelineEntry]   = []
    overall_confidence:    float                 = Field(ge=0, le=1, default=0.5)
    confidence_explanation: str                  = ""
    analyzed_by:           str                   = "local"
    cloud_enrichments:     list[str]             = []
    raw_response:          str                   = ""


# ── Incident ──────────────────────────────────────────────────────────────────

class Incident(BaseModel):
    id:                     str           = ""
    title:                  str
    status:                 IncidentStatus = IncidentStatus.NEW
    severity:               Severity       = Severity.MEDIUM
    created_at:             datetime       = Field(default_factory=datetime.utcnow)
    updated_at:             datetime       = Field(default_factory=datetime.utcnow)
    affected_hosts:         list[str]      = []
    description:            str            = ""
    analyst_notes:          str            = ""
    # Per-finding triage layer, keyed by finding id → {verdict, note,
    # updated_at}. Verdict is one of: true_positive, false_positive, benign,
    # needs_review. Sits on top of the detection findings (which live in
    # raw_artifacts) so marking a finding never mutates the detection output.
    finding_triage:         dict[str, Any] = {}
    analysis:               AnalysisResult | None          = None
    escalation:             EscalationDecision | None      = None
    anonymization_mappings: list[AnonymizationMapping]     = []
    raw_artifacts:          dict[str, Any]                 = {}
    # Audit / versioning — know which engine produced the findings
    engine_version:         str            = ""
    analyzed_at:            str            = ""


# ── API request / response ────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    incident_id:     str | None = None
    title:           str        = "Untitled incident"
    raw_data:        str
    data_type:       DataType   = DataType.MIXED
    context:         str        = ""
    allow_cloud:     bool       = True
    cloud_threshold: float      = 0.7


class HealthResponse(BaseModel):
    status:                 str
    lm_studio_reachable:    bool
    lm_studio_model:        str | None = None
    claude_api_configured:  bool


class PipelineStats(BaseModel):
    pii_items_redacted:      int   = 0
    anonymization_model:     str   = ""
    local_analysis_confidence: float = 0.0
    gaps_found:              int   = 0
    gaps_resolved_locally:   int   = 0
    gaps_sent_to_cloud:      int   = 0
    cloud_used:              bool  = False
