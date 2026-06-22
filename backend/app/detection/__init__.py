"""
detection/ — modular forensic detection engine.

Package layout (one logical concern per file):
  base.py                — DetectionEngine core, shared signatures, routing
  processes.py            — process/service/scheduled-task detection
  network.py               — network connection detection (ports, beaconing)
  dns_dga.py                — DNS/DGA/tunneling detection
  eventlogs.py               — core Windows Event Log detection
  auth_patterns.py            — advanced authentication pattern analysis
  defender.py                  — ALL Windows Defender detection (EVTX + MPLog)
  persistence.py                — registry persistence + LNK analysis
  execution_evidence.py          — Prefetch/Amcache/Shimcache/UserAssist/Shellbags
  file_anomalies.py               — file metadata anomaly detection
  generic.py                       — fallback for unrecognized artifacts
  behavior_correlation.py           — cross-finding attack chain detection
  risk_scoring.py                    — process/entity risk aggregation
  clustering.py                       — group findings into one entity

Adding a NEW detector module: write detect_foo(engine, key, rows) in a new
file, import it below, and add one register_route(...) call. Nothing else
in this package needs to change — base.py's dispatch loop is routing-table
driven specifically so this stays true as the engine grows.

This module re-exports DetectionEngine, ENGINE_VERSION, and
build_llm_context so existing code (orchestrator.py, services.py) that does
`from app.detection_engine import DetectionEngine, build_llm_context,
ENGINE_VERSION` keeps working — see the compatibility shim at
app/detection_engine.py.
"""

from __future__ import annotations

from app.detection.base import (
    DetectionEngine, ENGINE_VERSION, register_route, register_additional_pass,
)
from app.detection.clustering import _cluster_findings_by_folder

from app.detection.processes import detect_processes, detect_services, detect_tasks
from app.detection.network import detect_network
from app.detection.dns_dga import detect_dns_anomalies
from app.detection.eventlogs import detect_eventlogs
from app.detection.auth_patterns import detect_auth_patterns
from app.detection.defender import detect_mplog_events
from app.detection.persistence import detect_persistence_registry, detect_lnk
from app.detection.execution_evidence import (
    detect_execution, detect_shimcache, detect_userassist, detect_shellbags,
)
from app.detection.file_anomalies import detect_file_anomalies
from app.detection.yara_findings import detect_yara_matches
from app.detection.generic import detect_generic  # noqa: F401 — used as fallback in base.py


# ══════════════════════════════════════════════════
# Route registration — order matters (first match wins)
# ══════════════════════════════════════════════════
#
# This is the routing table that used to be a long if/elif chain inside
# DetectionEngine.analyze(). Each entry maps artifact-key substrings to the
# detector that handles them. More specific matches are registered before
# broader ones so they don't get swallowed (e.g. "shimcache" before the
# generic "prefetch|amcache" execution-evidence bucket).

register_route(["yara_matches", "yara"], detect_yara_matches)
register_route(["pslist", "process", "pstree"], detect_processes)
register_route(["dns"], detect_dns_anomalies)
register_route(["netstat", "network", "connection"], detect_network)
register_route(["service", "executable"], detect_services)
register_route(["scheduledtask", "task", "command"], detect_tasks)
register_route(["mplog", "defender_mplogs"], detect_mplog_events)
register_route(["evtx", "eventlog", "event", "logon"], detect_eventlogs)
register_route(["shimcache", "appcompatcache"], detect_shimcache)
register_route(["userassist"], detect_userassist)
register_route(["shellbag"], detect_shellbags)
register_route(["prefetch", "amcache"], detect_execution)
register_route(["registry", "run", "autorun", "startup"], detect_persistence_registry)
register_route(["lnk", "shortcut"], detect_lnk)
register_route(["searchglobs", "matches", "metadata", "upload"], detect_file_anomalies)

# Additional passes run ALONGSIDE whichever primary route matched, for the
# same artifact key — auth-pattern analysis runs whenever an eventlog
# route fires, without replacing detect_eventlogs's own brute-force check.
register_additional_pass(["evtx", "eventlog", "event", "logon"], detect_auth_patterns)


# ══════════════════════════════════════════════════
# LLM context builder
# ══════════════════════════════════════════════════

def build_llm_context(detection_result: dict, max_findings: int = 200) -> str:
    """
    Build a comprehensive but token-efficient context for the LLM
    from detection findings. Includes ALL high/critical findings plus
    representative samples of lower-severity ones.
    """
    lines = []
    lines.append("=== AUTOMATED FORENSIC DETECTION RESULTS ===")
    lines.append(f"Total findings: {detection_result['total_findings']}")
    lines.append(f"Critical: {detection_result['critical_count']}, "
                f"High: {detection_result['high_count']}, "
                f"Medium: {detection_result['medium_count']}")
    lines.append("")

    behavioral = detection_result.get("behavioral_summary", {})
    if behavioral.get("attack_chains"):
        lines.append("=== ATTACK CHAINS DETECTED ===")
        for chain in behavioral["attack_chains"]:
            lines.append(f"  • {chain}")
        lines.append("")

    if behavioral.get("findings_by_category"):
        lines.append("=== FINDINGS BY CATEGORY ===")
        for cat, count in sorted(behavioral["findings_by_category"].items(),
                                  key=lambda x: -x[1]):
            lines.append(f"  {cat}: {count}")
        lines.append("")

    corr_bits = []
    if behavioral.get("timeline_clusters"):
        corr_bits.append(f"{behavioral['timeline_clusters']} timeline activity bursts")
    if behavioral.get("suspicious_process_chains"):
        corr_bits.append(f"{behavioral['suspicious_process_chains']} suspicious process chains")
    if behavioral.get("frequency_outliers"):
        corr_bits.append(f"{behavioral['frequency_outliers']} rare/outlier artifacts")
    if corr_bits:
        lines.append("=== CROSS-DATASET CORRELATION ===")
        for bit in corr_bits:
            lines.append(f"  • {bit}")
        lines.append("")

    # Explicit same-folder/same-tool clustering — see clustering.py. Fix for
    # findings that ARE individually low-signal but collectively
    # significant (e.g. 4 "rare executable" findings that are actually 4
    # binaries from the same installed tool). Surfacing this BEFORE the
    # flat findings list means the LLM doesn't have to spot the pattern
    # itself by comparing long paths character-by-character.
    clusters = _cluster_findings_by_folder(detection_result["findings"])
    if clusters:
        lines.append("=== FINDINGS SHARING THE SAME FOLDER (likely one entity, not N) ===")
        lines.append(
            "The following finding groups share a parent folder. Findings in the "
            "same group very likely represent ONE installed tool or one staging "
            "event, not independent occurrences — treat them as a single entity "
            "in your analysis rather than N separate low-confidence items."
        )
        for cluster in clusters[:15]:  # cap to keep context bounded
            ids = ", ".join(f"[{i}]" for i in cluster["finding_ids"])
            lines.append(f"  • {cluster['count']}× findings in '{cluster['folder']}': {ids}")
        lines.append("")

    lines.append("=== DETAILED FINDINGS (with evidence pointers) ===")
    for finding in detection_result["findings"][:max_findings]:
        occ = finding.get("occurrences", 1)
        occ_str = f" | seen {occ}× (deduplicated)" if occ > 1 else ""
        lines.append(
            f"\n[{finding['id']}] {finding['severity'].upper()} | "
            f"{finding['category']} | MITRE: {finding['mitre'] or 'N/A'}{occ_str}"
        )
        lines.append(f"  Title: {finding['title']}")
        lines.append(f"  Detail: {finding['description']}")
        locator = finding["evidence"].get("locator") or f"{finding['artifact']} (row {finding['evidence'].get('row_index', 'N/A')})"
        lines.append(f"  Evidence location: {locator}")
        ev = finding["evidence"]
        ev_parts = []
        for k in ["name", "path", "cmdline", "command", "remote", "key", "value", "timestamp"]:
            if k in ev and ev[k]:
                ev_parts.append(f"{k}={str(ev[k])[:150]}")
        if ev_parts:
            lines.append(f"  Evidence: {' | '.join(ev_parts)}")

    if detection_result["total_findings"] > max_findings:
        lines.append(f"\n... and {detection_result['total_findings'] - max_findings} more findings "
                    f"(lower severity, omitted for brevity)")

    lines.append("\n=== COLLECTION STATISTICS ===")
    for key, val in detection_result.get("statistics", {}).items():
        if key.endswith("_total_rows"):
            lines.append(f"  {key.replace('_total_rows', '')}: {val} rows analyzed")

    return "\n".join(lines)


__all__ = ["DetectionEngine", "ENGINE_VERSION", "build_llm_context"]
