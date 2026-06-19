"""
detection/risk_scoring.py — process/entity risk aggregation.

Problem this solves (confirmed empirically across 5 generations of reports
on a real 60GB collection): individual findings each carry their own score,
but nothing aggregates them. A process with 3 separate medium-severity
findings (LOLBin usage + suspicious path + suspicious network connection)
looks no more important in the findings list than 3 unrelated medium
findings on 3 different processes — even though the first case is a much
stronger signal of compromise than three isolated coincidences.

This is a POST-PROCESSING pass, not a per-row detector: it runs once after
all other detectors have populated engine.findings, and emits SUMMARY
findings for any process/entity whose combined signal crosses a threshold.
It does not modify or remove the original findings — those stay as the
detailed evidence; this adds a higher-level "here's the story" layer on
top, the same way correlation_engine.py's attack-chain detection adds a
layer on top of individual Sigma/heuristic hits.

Identity resolution strategy: PID is the primary grouping key when present
(most reliable within a single collection), with process name+path as a
fallback/secondary key — this catches cases where the SAME binary shows up
across artifacts that don't carry a PID at all (e.g. Prefetch execution
evidence vs. a live process listing), which a PID-only approach would miss
entirely.
"""

from __future__ import annotations
import logging
from collections import defaultdict

logger = logging.getLogger(__name__)

# A process needs at least this many DISTINCT finding categories
# corroborating it before we treat it as a cumulative-risk entity worth a
# summary finding — a single category repeated (e.g. 5 "rare path" hits on
# unrelated files that happen to share a PID by coincidence of reuse)
# isn't the same kind of signal as "this PID has a suspicious path AND a
# C2-port connection AND a persistence mechanism".
MIN_CORROBORATING_CATEGORIES = 2

# Cumulative score threshold to emit a summary finding. Deliberately above
# what a single strong finding alone would produce (most individual
# findings here score 40-95), so this fires on genuine MULTI-SIGNAL
# corroboration, not as a duplicate of an existing high/critical finding.
RISK_SCORE_THRESHOLD = 130


def _entity_key(finding: dict) -> tuple[str, str] | None:
    """
    Resolve a grouping key for a finding: (kind, value) where kind is
    'pid' or 'name' depending on what's available. Returns None for
    findings with no usable process identity at all (e.g. a pure DNS or
    registry-key finding with nothing process-like in its evidence).
    """
    ev = finding.get("evidence", {})

    pid = ev.get("pid")
    if pid and str(pid).strip() and str(pid) != "?":
        return ("pid", str(pid))

    name = ev.get("name") or ev.get("process")
    if name and str(name).strip():
        # Normalize to just the binary name (strip any path that leaked in)
        clean = str(name).split("\\")[-1].split("/")[-1].lower().strip()
        if clean and clean not in ("", "unknown"):
            return ("name", clean)

    return None


def aggregate_process_risk(engine) -> None:
    """
    Post-processing pass: group engine.findings by process identity,
    compute cumulative risk per entity, and emit summary findings for
    entities that cross the corroboration threshold.

    Called from base.py's analyze() after all detector modules have run
    but before deduplication, so summary findings participate in the same
    sort/dedup/coverage pipeline as everything else.
    """
    groups: dict[tuple[str, str], list[dict]] = defaultdict(list)

    for f in engine.findings:
        # Don't fold MPLog/Defender/DNS/auth summary-style findings into
        # process grouping — they're not about a single running process,
        # and "Defender configuration changed" sharing a PID by accident
        # with an unrelated process would produce a misleading group.
        if f.get("category") in ("defense_evasion",) and "Defender" in f.get("title", ""):
            continue
        key = _entity_key(f)
        if key:
            groups[key].append(f)

    summaries_emitted = 0
    for (kind, value), group_findings in groups.items():
        categories = {f["category"] for f in group_findings}
        if len(categories) < MIN_CORROBORATING_CATEGORIES:
            continue

        total_score = sum(f.get("score", 0) for f in group_findings)
        if total_score < RISK_SCORE_THRESHOLD:
            continue

        # Build a readable summary of what corroborates this entity
        finding_ids = [f["id"] for f in group_findings]
        mitre_techniques = sorted({f["mitre"] for f in group_findings if f.get("mitre")})
        max_severity = min(
            (f["severity"] for f in group_findings),
            key=lambda s: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5),
        )

        category_breakdown = ", ".join(sorted(categories))
        label = f"PID {value}" if kind == "pid" else f"process '{value}'"

        engine._add_finding(
            "correlated_risk",
            # Summary severity tracks the strongest individual signal, but
            # is never lower than 'high' — multi-signal corroboration on
            # one entity is inherently a stronger story than any single
            # finding suggests in isolation.
            max_severity if max_severity in ("critical", "high") else "high",
            f"Cumulative risk: {label} corroborated by {len(categories)} finding categories",
            f"{label} is implicated in {len(group_findings)} separate findings spanning "
            f"{len(categories)} distinct categories ({category_breakdown}), with a combined "
            f"risk score of {total_score}. This level of cross-category corroboration on a "
            f"single entity is a stronger compromise indicator than any individual finding "
            f"alone — review the full chain: {', '.join(finding_ids)}.",
            "correlated",
            {
                "entity_kind": kind, "entity_value": value,
                "finding_ids": finding_ids, "category_count": len(categories),
                "categories": sorted(categories), "combined_score": total_score,
                "mitre_techniques": mitre_techniques,
            },
            score=min(total_score, 99),  # cap displayed score at 99
            mitre=mitre_techniques[0] if mitre_techniques else "",
        )
        summaries_emitted += 1

    if summaries_emitted:
        logger.info(
            f"Process risk aggregation: {summaries_emitted} entity summary finding(s) "
            f"emitted from {len(groups)} candidate group(s)"
        )
