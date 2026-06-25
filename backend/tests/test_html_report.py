"""
Tests for the HTML report renderer.

The HTML report is a presentation layer over the same dict the Markdown/JSON
report uses, so these tests focus on: it renders without error from a minimal
report, it escapes user/finding content (no HTML injection from artefact
names), it embeds findings for the client-side filter, and it degrades to
empty-state copy when sections are missing.
"""
from app.html_report import generate_html


def _minimal_report(**over):
    base = {
        "metadata": {"report_id": "IR-test", "title": "T", "severity": "high",
                     "status": "triage", "analyzed_by": "local", "confidence": "70%"},
        "executive_summary": {"bottom_line": "bl", "summary": "s",
                              "key_metrics": {"unique_findings": 1, "critical": 0, "high": 1}},
        "mitre_coverage": {}, "mitre_techniques": [], "iocs": [],
        "timeline": [], "recommendations": [], "knowledge_gaps": [],
        "attack_narrative": {}, "detection_findings": [],
    }
    base.update(over)
    return base


def test_renders_minimal_report():
    out = generate_html(_minimal_report())
    assert "<!DOCTYPE html>" in out
    assert "IR-test" in out
    assert "HIGH" in out  # severity tag


def test_escapes_finding_content():
    """An artefact name with HTML must not break out into markup."""
    evil = '<script>alert(1)</script>'
    report = _minimal_report(detection_findings=[
        {"id": "F1", "title": evil, "severity": "high", "category": "c",
         "description": "d", "mitre": "", "occurrences": 1, "score": 1},
    ])
    out = generate_html(report)
    # The raw <script> tag must be escaped somewhere in the embedded JSON/markup.
    assert "<script>alert(1)</script>" not in out
    assert "alert(1)" in out  # content preserved, just escaped


def test_embeds_findings_for_filter():
    report = _minimal_report(detection_findings=[
        {"id": "F0042", "title": "t", "severity": "critical", "category": "c",
         "description": "d", "mitre": "T1000", "occurrences": 2, "score": 9},
    ])
    out = generate_html(report)
    assert "F0042" in out
    assert "const FINDINGS" in out  # client-side filter data present


def test_empty_sections_show_empty_state():
    out = generate_html(_minimal_report())
    assert "No indicators of compromise" in out
    assert "No timeline events" in out


def test_severity_tints_document():
    """The headline severity drives the accent CSS variable."""
    crit = generate_html(_minimal_report(
        metadata={"report_id": "x", "title": "t", "severity": "critical",
                  "status": "s", "analyzed_by": "local", "confidence": "9%"}))
    assert "#ff4d4d" in crit  # critical hue wired into --accent
