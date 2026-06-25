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

# Cumulative score threshold to emit a summary finding lives in the central
# thresholds module now (see detection/thresholds.py) so all tuning constants
# sit in one place. Re-exported here under the original name for callers.
from app.detection.thresholds import RISK_SCORE_THRESHOLD


def _entity_keys(finding: dict) -> list[tuple[str, str]]:
    """
    Resolve ALL grouping keys for a finding — both ('pid', X) and
    ('name', Y) when both are available. Returning multiple keys is what
    lets a finding that only has a PID (e.g. a netstat connection) connect
    to a finding that only has a name (e.g. a YARA content hit) when they
    refer to the same binary: the process listing finding carries BOTH, so
    it bridges the two single-key findings during the merge step below.

    Returns an empty list for findings with no usable process identity.
    """
    ev = finding.get("evidence", {})
    keys = []

    pid = ev.get("pid")
    if pid and str(pid).strip() and str(pid) != "?":
        keys.append(("pid", str(pid)))

    name = ev.get("name") or ev.get("process")
    if name and str(name).strip():
        clean = str(name).split("\\")[-1].split("/")[-1].lower().strip()
        if clean and clean not in ("", "unknown"):
            keys.append(("name", clean))

    return keys


def aggregate_process_risk(engine) -> None:
    """
    Post-processing pass: group engine.findings by process identity,
    compute cumulative risk per entity, and emit summary findings for
    entities that cross the corroboration threshold.

    Uses a union-find-style merge so findings that share ANY identity key
    (PID or binary name) end up in the same group — this connects, e.g., a
    YARA content hit (name-only) to a process listing finding (pid+name)
    for the same binary, which a single-key approach would leave isolated.

    Called from base.py's analyze() after all detector modules have run
    but before deduplication, so summary findings participate in the same
    sort/dedup/coverage pipeline as everything else.
    """
    # Map each identity key to the set of finding indices that carry it.
    key_to_findings: dict[tuple[str, str], list[int]] = defaultdict(list)
    finding_keys: dict[int, list[tuple[str, str]]] = {}

    for i, f in enumerate(engine.findings):
        # Don't fold Defender summary-style findings into process grouping —
        # they're not about a single running process, and sharing a PID by
        # accident with an unrelated process would produce a misleading group.
        if f.get("category") in ("defense_evasion",) and "Defender" in f.get("title", ""):
            continue
        keys = _entity_keys(f)
        if keys:
            finding_keys[i] = keys
            for k in keys:
                key_to_findings[k].append(i)

    # Union-find: merge finding indices that share any key.
    parent: dict[int, int] = {}

    def find(x: int) -> int:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for indices in key_to_findings.values():
        for j in indices[1:]:
            union(indices[0], j)

    # Collect merged groups: root index → list of findings
    merged: dict[int, list[dict]] = defaultdict(list)
    merged_keys: dict[int, set] = defaultdict(set)
    for i in finding_keys:
        root = find(i)
        merged[root].append(engine.findings[i])
        merged_keys[root].update(finding_keys[i])

    summaries_emitted = 0
    for root, group_findings in merged.items():
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

        # Derive a human label from the group's keys — prefer a binary name
        # (more readable than a PID) when available, else fall back to PID.
        keys = merged_keys[root]
        name_keys = [v for (k, v) in keys if k == "name"]
        pid_keys = [v for (k, v) in keys if k == "pid"]
        if name_keys:
            label = f"process '{name_keys[0]}'"
            entity_kind, entity_value = "name", name_keys[0]
        else:
            label = f"PID {pid_keys[0]}"
            entity_kind, entity_value = "pid", pid_keys[0]

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
                "entity_kind": entity_kind, "entity_value": entity_value,
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
            f"emitted from {len(merged)} candidate group(s)"
        )
