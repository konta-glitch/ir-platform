"""
Tests for relationship-aware narrative batching.

group_findings_for_narrative keeps related findings (same folder/tool, MITRE
technique, or entity) in the same batch instead of slicing the flat list, so an
attack's findings reach the model together and it writes one coherent story.
"""
from app.detection.clustering import group_findings_for_narrative


def _noise(n):
    return [{"id": f"S{i:04d}", "severity": "low", "mitre": "N/A", "evidence": {}}
            for i in range(n)]


def test_shared_mitre_groups_together():
    findings = [
        {"id": "F1", "severity": "high", "mitre": "T1219", "evidence": {}},
        *_noise(20),
        {"id": "F2", "severity": "high", "mitre": "T1219", "evidence": {}},
    ]
    batches = group_findings_for_narrative(findings, batch_size=20)
    # Both T1219 findings land in the same batch despite the noise between them.
    home = [i for i, b in enumerate(batches)
            if any(f["id"] in ("F1", "F2") for f in b)]
    assert len(set(home)) == 1


def test_shared_entity_groups_together():
    findings = [
        {"id": "F1", "severity": "high", "mitre": "N/A",
         "evidence": {"process": "screenconnect.exe"}},
        *_noise(15),
        {"id": "F2", "severity": "medium", "mitre": "N/A",
         "evidence": {"process": "screenconnect.exe"}},
    ]
    batches = group_findings_for_narrative(findings, batch_size=20)
    home = [i for i, b in enumerate(batches)
            if any(f["id"] in ("F1", "F2") for f in b)]
    assert len(set(home)) == 1


def test_batches_respect_size_limit():
    findings = _noise(55)
    batches = group_findings_for_narrative(findings, batch_size=20)
    assert all(len(b) <= 20 for b in batches)
    # All findings are present exactly once.
    ids = [f["id"] for b in batches for f in b]
    assert sorted(ids) == sorted(f["id"] for f in findings)


def test_critical_component_leads():
    findings = [
        *_noise(5),
        {"id": "C1", "severity": "critical", "mitre": "T1", "evidence": {}},
    ]
    batches = group_findings_for_narrative(findings, batch_size=20)
    # The critical finding's component should be in the first batch.
    assert any(f["id"] == "C1" for f in batches[0])


def test_oversized_component_chunks_but_stays_adjacent():
    # 25 findings all sharing one MITRE id — bigger than batch_size.
    findings = [{"id": f"F{i}", "severity": "high", "mitre": "T1219",
                 "evidence": {}} for i in range(25)]
    batches = group_findings_for_narrative(findings, batch_size=20)
    assert all(len(b) <= 20 for b in batches)
    assert sum(len(b) for b in batches) == 25


def test_empty_input():
    assert group_findings_for_narrative([], batch_size=20) == []
