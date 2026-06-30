"""
Tests for the richer-evidence helpers used by both report formats.
"""
from app.evidence_format import why_it_matters, evidence_fields


def test_why_matches_category_specific():
    f = {"category": "malware_signature"}
    assert "content matched a malware rule" in why_it_matters(f)


def test_why_matches_substring_category():
    # "process_anomaly" should hit the "process_anomaly" entry.
    f = {"category": "process_anomaly"}
    assert "behaved unusually" in why_it_matters(f)


def test_why_falls_back_for_unknown_category():
    f = {"category": "totally_new_thing"}
    assert why_it_matters(f) == why_it_matters({"category": ""})  # default


def test_evidence_pulls_known_fields_in_order():
    f = {"evidence": {"row_index": 3, "path": "/x/y.exe", "name": "y.exe"}}
    fields = evidence_fields(f)
    labels = [lbl for lbl, _, _ in fields]
    # Path before Name before Row (defined order), Row last.
    assert labels.index("Path") < labels.index("Name") < labels.index("Row")


def test_matched_strings_flagged_raw():
    f = {"evidence": {"path": "/x", "matched_strings": "$stub1='binary...'"}}
    fields = evidence_fields(f)
    raw = [(lbl, raw) for lbl, _, raw in fields if raw]
    assert any("Matched strings" in lbl for lbl, _ in raw)
    # The path is NOT raw.
    path = next(r for lbl, _, r in fields if lbl == "Path")
    assert path is False


def test_locator_and_significance_skipped():
    f = {"evidence": {"locator": "x (row 1)", "significance": "y", "path": "/z"}}
    labels = [lbl for lbl, _, _ in evidence_fields(f)]
    assert "Locator" not in labels and "Significance" not in labels
    assert "Path" in labels


def test_unanticipated_field_still_shown():
    f = {"evidence": {"some_new_key": "value123"}}
    fields = evidence_fields(f)
    assert any(v == "value123" for _, v, _ in fields)  # not dropped


def test_long_unanticipated_field_marked_raw():
    f = {"evidence": {"blob": "x" * 200}}
    fields = evidence_fields(f)
    assert any(raw for _, _, raw in fields)  # >160 chars => raw


def test_list_value_stringified():
    f = {"evidence": {"args": ["--service", "--quiet"]}}
    val = next(v for lbl, v, _ in evidence_fields(f) if lbl == "Arguments")
    assert "--service" in val and "--quiet" in val
