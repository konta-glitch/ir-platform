"""
Tests that the agent parses the tool-call JSON reasoning models emit (even with
the spaces stripped) and never leaks raw protocol JSON into the chat answer.
"""
from app.investigation_agent import InvestigationAgent


def test_parses_space_stripped_json():
    # Exactly what DeepSeek-R1 returned: valid JSON but words run together.
    stuck = ('{"thought":"TofindIPaddresses","action":"get_findings",'
             '"args":{"severity":"medium","category":"sigma_detection"}}')
    d = InvestigationAgent._parse_json(stuck)
    assert d is not None
    assert d["action"] == "get_findings"
    assert d["args"]["severity"] == "medium"


def test_parses_json_with_prose_around_it():
    raw = 'Here is my decision:\n{"action":"search","args":{"query":"IP"}}\nDone.'
    d = InvestigationAgent._parse_json(raw)
    assert d["action"] == "search"


def test_parses_fenced_json():
    raw = '```json\n{"action":"answer","answer":"No IPs found."}\n```'
    d = InvestigationAgent._parse_json(raw)
    assert d["action"] == "answer"


def test_repairs_trailing_comma():
    raw = '{"action":"get_findings","args":{"severity":"high",}}'
    d = InvestigationAgent._parse_json(raw)
    assert d is not None
    assert d["action"] == "get_findings"


def test_plain_prose_returns_none():
    # No JSON at all -> None (caller treats as a genuine text answer).
    assert InvestigationAgent._parse_json("No IP addresses were found anywhere.") is None


def test_empty_returns_none():
    assert InvestigationAgent._parse_json("") is None
    assert InvestigationAgent._parse_json("   ") is None
