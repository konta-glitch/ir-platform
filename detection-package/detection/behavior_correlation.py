"""
detection/behavior_correlation.py — cross-finding attack chain detection.

Separate from individual detectors because it operates on the FULL set of
findings after all detectors have run, not on a single artifact's rows.
"""

from __future__ import annotations
from collections import Counter


def correlate_behavior(engine) -> dict:
    """
    Correlate findings across artifacts/categories to identify attack
    patterns. `engine` is the DetectionEngine instance (reads engine.findings,
    engine.evidence_index).
    """
    categories = Counter(f["category"] for f in engine.findings)
    mitre_tactics = Counter(f["mitre"] for f in engine.findings if f["mitre"])

    chains = []
    cats_present = set(categories.keys())

    if "execution" in cats_present and "persistence" in cats_present:
        chains.append("Execution + Persistence — attacker established a foothold and ensured survival")
    if "credential_access" in cats_present and "privilege_escalation" in cats_present:
        chains.append("Credential Access + Privilege Escalation — account compromise and elevation")
    if "credential_access" in cats_present and "lateral_movement" in cats_present:
        chains.append("Credential Access + Lateral Movement — attacker harvesting creds to spread")
    if "defense_evasion" in cats_present:
        chains.append("Defense Evasion detected — attacker actively covering tracks")
    if "network_anomaly" in cats_present and "execution" in cats_present:
        chains.append("Execution + Network anomaly — possible C2 communication channel")
    if "lateral_movement" in cats_present:
        chains.append("Lateral Movement detected — attacker moving between hosts")
    if "exfiltration" in cats_present:
        chains.append("Data staging/exfiltration indicators — potential data theft")

    kill_chain_stages = {"execution", "persistence", "privilege_escalation",
                         "defense_evasion", "credential_access", "lateral_movement"}
    present_stages = kill_chain_stages & cats_present
    if len(present_stages) >= 4:
        chains.insert(0, f"FULL ATTACK CHAIN — {len(present_stages)} kill-chain stages present: "
                     f"{', '.join(sorted(present_stages))}. Strong indication of a coordinated intrusion.")

    has_shadow_delete = any("shadow" in f["title"].lower() or "ransomware" in f["title"].lower()
                            for f in engine.findings)
    if has_shadow_delete:
        chains.append("RANSOMWARE INDICATORS — shadow copy deletion / encryption artifacts detected")

    return {
        "findings_by_category": dict(categories),
        "mitre_techniques_seen": dict(mitre_tactics.most_common(15)),
        "attack_chains": chains,
        "lolbin_usage_count": len(engine.evidence_index.get("lolbins", [])),
    }
