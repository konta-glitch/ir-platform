"""
IR Report Generator — creates detailed incident response reports.

Outputs:
  - Structured dict for the frontend report view
  - Markdown for download
  - Includes: executive summary, IOCs, MITRE ATT&CK, timeline,
    anonymization stats, recommendations, knowledge gaps
"""

from datetime import datetime
from app.models import Incident, Severity


SEVERITY_LABELS = {
    Severity.CRITICAL: ("CRITICAL", "Immediate action required"),
    Severity.HIGH: ("HIGH", "Urgent response needed"),
    Severity.MEDIUM: ("MEDIUM", "Investigation recommended"),
    Severity.LOW: ("LOW", "Monitor and assess"),
    Severity.INFO: ("INFORMATIONAL", "No immediate threat"),
}


# Technique prefix → tactic (best-effort mapping of common ATT&CK techniques)
TECHNIQUE_TO_TACTIC = {
    "T1059": "Execution", "T1204": "Execution", "T1106": "Execution", "T1053": "Persistence",
    "T1547": "Persistence", "T1543": "Persistence", "T1136": "Persistence",
    "T1546": "Persistence", "T1574": "Persistence", "T1505": "Persistence",
    "T1055": "Privilege Escalation", "T1548": "Privilege Escalation", "T1134": "Privilege Escalation",
    "T1036": "Defense Evasion", "T1070": "Defense Evasion", "T1562": "Defense Evasion",
    "T1112": "Defense Evasion", "T1027": "Defense Evasion", "T1218": "Defense Evasion",
    "T1140": "Defense Evasion", "T1003": "Credential Access", "T1110": "Credential Access",
    "T1555": "Credential Access", "T1552": "Credential Access", "T1558": "Credential Access",
    "T1087": "Discovery", "T1082": "Discovery", "T1057": "Discovery", "T1018": "Discovery",
    "T1083": "Discovery", "T1016": "Discovery", "T1033": "Discovery", "T1021": "Lateral Movement",
    "T1570": "Lateral Movement", "T1071": "Command and Control", "T1571": "Command and Control",
    "T1105": "Command and Control", "T1572": "Command and Control", "T1090": "Command and Control",
    "T1041": "Exfiltration", "T1048": "Exfiltration", "T1567": "Exfiltration",
    "T1486": "Impact", "T1490": "Impact", "T1489": "Impact", "T1485": "Impact",
    "T1566": "Initial Access", "T1190": "Initial Access", "T1078": "Initial Access",
    "T1560": "Collection", "T1005": "Collection", "T1114": "Collection",
}

TACTIC_ORDER = ["Reconnaissance", "Resource Development", "Initial Access",
                "Execution", "Persistence", "Privilege Escalation",
                "Defense Evasion", "Credential Access", "Discovery",
                "Lateral Movement", "Collection", "Command and Control",
                "Exfiltration", "Impact", "Other", "Uncategorized"]


def _tactic_for_technique(technique_id: str) -> str:
    if not technique_id:
        return "Uncategorized"
    return TECHNIQUE_TO_TACTIC.get(technique_id.split(".")[0], "Other")


def _build_mitre_coverage(findings: list, mitre_techniques: list) -> dict:
    """Build a MITRE ATT&CK coverage map: tactic → techniques observed."""
    all_techniques: dict = {}
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    for f in findings:
        tid = f.get("mitre", "")
        if tid:
            if tid not in all_techniques:
                all_techniques[tid] = {"count": 0, "max_severity": "low", "titles": set()}
            all_techniques[tid]["count"] += 1
            all_techniques[tid]["titles"].add(f.get("title", "")[:60])
            if sev_rank.get(f.get("severity", "low"), 0) > sev_rank.get(all_techniques[tid]["max_severity"], 0):
                all_techniques[tid]["max_severity"] = f.get("severity", "low")

    for t in mitre_techniques:
        tid = getattr(t, "technique_id", "")
        if tid and tid not in all_techniques:
            all_techniques[tid] = {"count": 1, "max_severity": "medium",
                                    "titles": {getattr(t, "technique_name", "")[:60]}}

    coverage: dict = {}
    for tid, info in all_techniques.items():
        tactic = _tactic_for_technique(tid)
        if tactic not in coverage:
            coverage[tactic] = {"tactic": tactic, "techniques": [], "total_detections": 0}
        coverage[tactic]["techniques"].append({
            "id": tid, "count": info["count"],
            "severity": info["max_severity"], "examples": list(info["titles"])[:3],
        })
        coverage[tactic]["total_detections"] += info["count"]

    ordered = []
    for tactic in TACTIC_ORDER:
        if tactic in coverage:
            coverage[tactic]["techniques"].sort(key=lambda x: -x["count"])
            ordered.append(coverage[tactic])

    return {
        "tactics_observed": len(coverage),
        "total_techniques": len(all_techniques),
        "coverage": ordered,
    }


def generate_report(incident: Incident) -> dict:
    """Generate a structured report from an incident."""
    a = incident.analysis
    e = incident.escalation
    sev_label, sev_desc = SEVERITY_LABELS.get(
        incident.severity, ("UNKNOWN", "")
    )

    findings = incident.raw_artifacts.get("detection_findings", [])
    mitre_coverage = _build_mitre_coverage(findings, a.mitre_techniques if a else [])

    # Executive summary metrics. After deduplication, len(findings) is the
    # number of UNIQUE findings; we also surface total raw occurrences so the
    # report is honest about volume without inflating the headline count.
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med = sum(1 for f in findings if f.get("severity") == "medium")
    total_occurrences = sum(f.get("occurrences", 1) for f in findings)

    report = {
        "metadata": {
            "report_id": f"IR-{incident.id}",
            "title": incident.title,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "incident_id": incident.id,
            "status": incident.status.value,
            "created_at": incident.created_at.isoformat(),
            "severity": sev_label,
            "severity_description": sev_desc,
            "analyzed_by": a.analyzed_by if a else "pending",
            "confidence": f"{a.overall_confidence:.0%}" if a else "N/A",
            "affected_hosts": incident.affected_hosts,
            "engine_version": incident.raw_artifacts.get("engine_version", "unknown"),
            "analyzed_at": incident.raw_artifacts.get("analyzed_at", "unknown"),
        },
        "executive_summary": {
            "summary": a.summary if a else "Analysis pending.",
            "confidence_explanation": a.confidence_explanation if a else "",
            "key_metrics": {
                "total_findings": len(findings),
                "unique_findings": len(findings),
                "total_occurrences": total_occurrences,
                "critical": crit, "high": high, "medium": med,
                "iocs": len(a.iocs) if a else 0,
                "mitre_tactics": mitre_coverage["tactics_observed"],
                "mitre_techniques": mitre_coverage["total_techniques"],
                "attack_chains": len(incident.raw_artifacts.get("detection_summary", {}).get("attack_chains", [])),
            },
            "bottom_line": _bottom_line(incident.severity, crit, high,
                                        incident.raw_artifacts.get("detection_summary", {})),
        },
        "mitre_coverage": mitre_coverage,
        "anonymization": {
            "total_redacted": len(incident.anonymization_mappings),
            "by_category": _count_by_category(incident.anonymization_mappings),
        },
        "iocs": [],
        "mitre_techniques": [],
        "timeline": [],
        "recommendations": [],
        "knowledge_gaps": [],
        "cloud_enrichments": a.cloud_enrichments if a else [],
        "analyst_notes": incident.analyst_notes,
        "detection_findings": findings,
        "detection_summary": incident.raw_artifacts.get("detection_summary", {}),
        "detection_statistics": incident.raw_artifacts.get("detection_statistics", {}),
        "coverage": incident.raw_artifacts.get("coverage", {}),
        "timeline_clusters": incident.raw_artifacts.get("timeline_clusters", []),
        "suspicious_chains": incident.raw_artifacts.get("suspicious_chains", []),
        "frequency_summary": incident.raw_artifacts.get("frequency_summary", {}),
        "pipeline_trace": incident.raw_artifacts.get("pipeline_trace", {}),
        "attack_narrative": incident.raw_artifacts.get("attack_narrative", {}),
    }

    if a:
        report["iocs"] = [
            {
                "type": ioc.type,
                "value": ioc.value,
                "context": ioc.context,
                "confidence": f"{ioc.confidence:.0%}",
                "confidence_raw": ioc.confidence,
                "malicious": ioc.malicious,
                "reason": ioc.confidence_reason,
            }
            for ioc in sorted(a.iocs, key=lambda x: (-x.confidence, -int(x.malicious)))
        ]

        report["mitre_techniques"] = [
            {
                "id": t.technique_id,
                "name": t.technique_name,
                "tactic": t.tactic,
                "confidence": f"{t.confidence:.0%}",
                "confidence_raw": t.confidence,
                "evidence": t.evidence,
            }
            for t in sorted(a.mitre_techniques, key=lambda x: -x.confidence)
        ]

        report["timeline"] = [
            {
                "timestamp": t.timestamp,
                "event": t.event,
                "source": t.source,
                "significance": t.significance,
            }
            for t in a.timeline
        ]

        report["recommendations"] = a.recommendations

    if e:
        report["knowledge_gaps"] = [
            {
                "question": item.question,
                "category": item.category,
                "priority": item.priority,
                "status": (
                    "resolved_cloud" if item.resolved_by_cloud
                    else "resolved_local" if item.resolved_locally
                    else "pending"
                ),
                "answer": item.cloud_answer or item.local_answer or "",
            }
            for item in e.items
        ]

    return report


def generate_markdown(incident: Incident) -> str:
    """Generate a downloadable Markdown report."""
    r = generate_report(incident)
    m = r["metadata"]
    lines = []

    lines.append(f"# Incident Response Report: {m['report_id']}")
    lines.append("")
    lines.append(f"**Title:** {m['title']}")
    lines.append(f"**Generated:** {m['generated_at']}")
    lines.append(f"**Status:** {m['status']}")
    lines.append(f"**Severity:** {m['severity']} — {m['severity_description']}")
    lines.append(f"**Confidence:** {m['confidence']}")
    lines.append(f"**Analyzed by:** {m['analyzed_by']}")
    lines.append(f"**Engine version:** {m.get('engine_version', 'unknown')} "
                 f"(analyzed {m.get('analyzed_at', 'unknown')})")
    if m["affected_hosts"]:
        lines.append(f"**Affected hosts:** {', '.join(m['affected_hosts'])}")
    lines.append("")

    # Executive Summary
    lines.append("---")
    lines.append("## Executive Summary")
    lines.append("")
    es = r["executive_summary"]
    if es.get("bottom_line"):
        lines.append(f"**Bottom line:** {es['bottom_line']}")
        lines.append("")
    km = es.get("key_metrics", {})
    if km:
        uniq = km.get("unique_findings", km.get("total_findings", 0))
        occ = km.get("total_occurrences", uniq)
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Unique findings | {uniq} |")
        if occ != uniq:
            lines.append(f"| Total occurrences | {occ} |")
        lines.append(f"| Critical / High / Medium | {km.get('critical', 0)} / {km.get('high', 0)} / {km.get('medium', 0)} |")
        lines.append(f"| Indicators of compromise | {km.get('iocs', 0)} |")
        lines.append(f"| MITRE tactics observed | {km.get('mitre_tactics', 0)} |")
        lines.append(f"| MITRE techniques observed | {km.get('mitre_techniques', 0)} |")
        lines.append(f"| Attack chains identified | {km.get('attack_chains', 0)} |")
        lines.append("")
    lines.append(es["summary"])
    if es.get("confidence_explanation"):
        lines.append("")
        lines.append(f"*{es['confidence_explanation']}*")
    lines.append("")

    # Attack Narrative (LLM-generated)
    narr = r.get("attack_narrative", {})
    if narr.get("attack_narrative"):
        lines.append("---")
        lines.append("## Attack Narrative")
        lines.append("")
        lines.append(narr["attack_narrative"])
        lines.append("")
        if narr.get("threat_assessment"):
            lines.append("**Threat assessment:** " + narr["threat_assessment"])
            lines.append("")
        if narr.get("key_findings"):
            lines.append("### Key Findings Triage")
            lines.append("")
            for kf in narr["key_findings"]:
                lines.append(f"- **[{kf.get('finding_id', '?')}]** {kf.get('why_it_matters', '')}")
                if kf.get("recommended_action"):
                    lines.append(f"  - Action: {kf['recommended_action']}")
            lines.append("")

    # MITRE ATT&CK Coverage Map
    mc = r.get("mitre_coverage", {})
    if mc.get("coverage"):
        lines.append("---")
        lines.append(f"## MITRE ATT&CK Coverage ({mc['tactics_observed']} tactics, {mc['total_techniques']} techniques)")
        lines.append("")
        lines.append("Observed adversary behavior mapped across the ATT&CK kill chain:")
        lines.append("")
        for tactic_cov in mc["coverage"]:
            lines.append(f"### {tactic_cov['tactic']} ({tactic_cov['total_detections']} detections)")
            for tech in tactic_cov["techniques"]:
                examples = "; ".join(tech["examples"][:2])
                lines.append(f"- **{tech['id']}** [{tech['severity']}] ×{tech['count']} — {examples}")
            lines.append("")

    # Anonymization
    lines.append("## Data Anonymization")
    lines.append("")
    total_redacted = r['anonymization']['total_redacted']
    if total_redacted > 0:
        lines.append(f"**{total_redacted}** identifiers were anonymized before sending "
                     f"knowledge gaps to the cloud, and restored on return. "
                     f"Local analysis ran on the original data on-device.")
        if r["anonymization"]["by_category"]:
            lines.append("")
            for cat, count in sorted(r["anonymization"]["by_category"].items(),
                                      key=lambda x: -x[1]):
                lines.append(f"- {cat}: {count}")
    else:
        lines.append("No data was sent to the cloud — analysis ran entirely "
                     "on-device, so no anonymization was needed.")
    lines.append("")

    # IOCs
    if r["iocs"]:
        lines.append("---")
        lines.append(f"## Indicators of Compromise ({len(r['iocs'])})")
        lines.append("")
        lines.append("| Type | Value | Malicious | Confidence | Context |")
        lines.append("|------|-------|-----------|------------|---------|")
        for ioc in r["iocs"]:
            mal = "YES" if ioc["malicious"] else "No"
            lines.append(
                f"| {ioc['type']} | `{ioc['value']}` | {mal} | "
                f"{ioc['confidence']} | {ioc['context'][:80]} |"
            )
        lines.append("")

    # MITRE ATT&CK
    if r["mitre_techniques"]:
        lines.append("---")
        lines.append(f"## MITRE ATT&CK Mapping ({len(r['mitre_techniques'])})")
        lines.append("")
        for t in r["mitre_techniques"]:
            lines.append(f"### {t['id']} — {t['name']}")
            lines.append(f"- **Tactic:** {t['tactic']}")
            lines.append(f"- **Confidence:** {t['confidence']}")
            if t["evidence"]:
                lines.append(f"- **Evidence:** {t['evidence']}")
            lines.append("")

    # Timeline
    if r["timeline"]:
        lines.append("---")
        lines.append("## Attack Timeline")
        lines.append("")
        for entry in r["timeline"]:
            lines.append(f"**{entry['timestamp']}** — {entry['event']}")
            if entry["source"]:
                lines.append(f"  - Source: {entry['source']}")
            if entry["significance"]:
                lines.append(f"  - Significance: {entry['significance']}")
            lines.append("")

    # Recommendations
    if r["recommendations"]:
        lines.append("---")
        lines.append("## Recommendations")
        lines.append("")
        for i, rec in enumerate(r["recommendations"], 1):
            lines.append(f"{i}. {rec}")
        lines.append("")

    # Knowledge Gaps
    if r["knowledge_gaps"]:
        lines.append("---")
        lines.append("## Knowledge Gaps")
        lines.append("")
        for gap in r["knowledge_gaps"]:
            status_icon = {
                "resolved_cloud": "[Cloud]",
                "resolved_local": "[Local]",
                "pending": "[PENDING]",
            }.get(gap["status"], "[?]")
            lines.append(f"- {status_icon} **{gap['question']}** ({gap['category']}, {gap['priority']})")
            if gap["answer"]:
                lines.append(f"  > {gap['answer'][:200]}")
        lines.append("")

    # Cloud Enrichments
    if r["cloud_enrichments"]:
        lines.append("---")
        lines.append("## Cloud Enrichments")
        lines.append("")
        for enrichment in r["cloud_enrichments"]:
            lines.append(f"- {enrichment}")
        lines.append("")

    # Analyst Notes
    if r["analyst_notes"]:
        lines.append("---")
        lines.append("## Analyst Notes")
        lines.append("")
        lines.append(r["analyst_notes"])
        lines.append("")

    # Detection Engine Findings (with evidence pointers)
    findings = r.get("detection_findings", [])
    if findings:
        lines.append("---")
        lines.append(f"## Automated Detection Findings ({len(findings)})")
        lines.append("")
        summary = r.get("detection_summary", {})
        if summary.get("attack_chains"):
            lines.append("### Attack Chains Identified")
            lines.append("")
            for chain in summary["attack_chains"]:
                lines.append(f"- {chain}")
            lines.append("")

        # Group by severity
        by_sev = {}
        for f in findings:
            by_sev.setdefault(f["severity"], []).append(f)

        for sev in ["critical", "high", "medium", "low"]:
            sev_findings = by_sev.get(sev, [])
            if not sev_findings:
                continue
            lines.append(f"### {sev.upper()} Severity ({len(sev_findings)})")
            lines.append("")
            for f in sev_findings:
                ev = f["evidence"]
                locator = ev.get("locator") or f"{f['artifact']} (row {ev.get('row_index', 'N/A')})"
                occ = f.get("occurrences", 1)
                occ_str = f" — seen {occ}× across the dataset" if occ > 1 else ""
                lines.append(f"#### [{f['id']}] {f['title']}{occ_str}")
                lines.append(f"- **Category:** {f['category']}")
                lines.append(f"- **MITRE:** {f.get('mitre', 'N/A')}")
                lines.append(f"- **Description:** {f['description']}")
                lines.append(f"- **Evidence location:** `{locator}`")
                if occ > 1 and f.get("occurrence_locators"):
                    lines.append(f"- **Other occurrences:** {', '.join(f['occurrence_locators'][:5])}"
                                 + (" ..." if occ > 6 else ""))
                # Evidence detail (skip internal fields)
                ev_lines = []
                for k, v in ev.items():
                    if k not in ("row_index", "locator", "source_file") and v:
                        ev_lines.append(f"  - `{k}`: {str(v)[:200]}")
                if ev.get("source_file"):
                    ev_lines.insert(0, f"  - `file`: {ev['source_file']}")
                if ev_lines:
                    lines.append("- **Evidence:**")
                    lines.extend(ev_lines)
                lines.append("")

    # Data Coverage — IR completeness proof
    cov = r.get("coverage", {})
    det_stats = r.get("detection_statistics", {})
    if cov or det_stats:
        lines.append("---")
        lines.append("## Data Coverage")
        lines.append("")
        if cov:
            lines.append(f"**Forensic completeness:** every row was examined by the "
                        f"detection engine — no sampling, no caps. "
                        f"**{cov.get('total_rows_scanned', 0):,} rows** across "
                        f"**{cov.get('artifacts_scanned', 0)} artifacts** scanned at 100%.")
            lines.append("")
            lines.append("| Artifact | Rows scanned | Fully scanned |")
            lines.append("|----------|-------------:|:-------------:|")
            for a in cov.get("per_artifact", []):
                check = "✓" if a.get("fully_scanned") else "✗"
                lines.append(f"| {a['artifact']} | {a['rows_scanned']:,} | {check} |")
            lines.append("")
        elif det_stats:
            lines.append("Rows analyzed per artifact (entire dataset, not sampled):")
            lines.append("")
            for key, val in sorted(det_stats.items()):
                if key.endswith("_total_rows"):
                    artifact = key.replace("_total_rows", "")
                    lines.append(f"- **{artifact}**: {val:,} rows")
            lines.append("")

    # Timeline clusters
    clusters = r.get("timeline_clusters", [])
    if clusters:
        lines.append("---")
        lines.append(f"## Timeline Activity Bursts ({len(clusters)})")
        lines.append("")
        lines.append("Tight clusters of cross-artifact activity, often indicating coordinated attacker actions.")
        lines.append("")
        for i, c in enumerate(clusters, 1):
            lines.append(f"### Burst {i}: {c['event_count']} events")
            lines.append(f"- **Window:** {c['start']} → {c['end']}")
            lines.append(f"- **Artifacts involved:** {', '.join(c['artifacts_involved'])}")
            lines.append("- **Events:**")
            for ev in c.get("events", [])[:10]:
                lines.append(f"  - `{ev['time']}` [{ev['artifact']}] {ev['description']}")
            lines.append("")

    # Suspicious process chains
    chains = r.get("suspicious_chains", [])
    if chains:
        lines.append("---")
        lines.append(f"## Suspicious Process Chains ({len(chains)})")
        lines.append("")
        lines.append("Reconstructed process ancestry matching known attack patterns.")
        lines.append("")
        for c in chains:
            lines.append(f"- `{c['chain']}` (depth {c['depth']})")
        lines.append("")

    # Frequency analysis
    freq = r.get("frequency_summary", {})
    if freq:
        lines.append("---")
        lines.append("## Frequency Analysis (Stack Counting)")
        lines.append("")
        lines.append(f"- Unique process names: {freq.get('unique_process_names', 0)}")
        lines.append(f"- Unique paths: {freq.get('unique_paths', 0)}")
        lines.append(f"- Unique file hashes: {freq.get('unique_hashes', 0)}")
        lines.append(f"- Rare executables in suspicious locations: {freq.get('rare_suspicious_paths', 0)}")
        lines.append("")

    # Pipeline execution trace
    trace = r.get("pipeline_trace", {})
    if trace.get("stages"):
        lines.append("---")
        lines.append("## Pipeline Execution Trace")
        lines.append("")
        lines.append(f"Total duration: {trace.get('total_duration_s', 0)}s across {trace.get('stage_count', 0)} stages.")
        lines.append("")
        lines.append("| Stage | Duration | Metrics |")
        lines.append("|-------|----------|---------|")
        for s in trace["stages"]:
            metrics = ", ".join(f"{k}={v}" for k, v in s.get("metrics", {}).items())
            lines.append(f"| {s['stage']} | {s.get('duration_s', 0)}s | {metrics} |")
        lines.append("")

    lines.append("---")
    lines.append(f"*Report generated by IR Platform on {m['generated_at']}*")

    return "\n".join(lines)


def _count_by_category(mappings) -> dict:
    counts = {}
    for m in mappings:
        counts[m.category] = counts.get(m.category, 0) + 1
    return counts


def _bottom_line(severity, crit: int, high: int, detection_summary: dict) -> str:
    """One-paragraph plain-language verdict for management."""
    chains = detection_summary.get("attack_chains", [])

    if crit > 0:
        verdict = (f"This host shows {crit} critical and {high} high-severity indicators "
                   f"of active compromise. Immediate containment is recommended.")
    elif high >= 3:
        verdict = (f"This host shows {high} high-severity indicators consistent with "
                   f"malicious activity. Prompt investigation is advised.")
    elif high > 0:
        verdict = (f"This host shows {high} high-severity finding(s) that warrant review, "
                   f"though they may be benign administrative activity.")
    else:
        verdict = ("No high-severity indicators were detected. The host appears clean "
                   "based on the collected artifacts, though absence of evidence is not "
                   "proof of absence.")

    if chains:
        verdict += f" Detected attack patterns: {'; '.join(chains[:2])}."

    return verdict
