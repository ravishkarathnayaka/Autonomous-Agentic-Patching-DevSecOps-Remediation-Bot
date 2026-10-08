"""Unit tests for Bandit SAST report parser."""

from pathlib import Path
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.bandit_parser import parse_bandit_report


def test_parse_bandit_report():
    fixture_path = Path(__file__).parent / "fixtures" / "bandit_findings.json"
    findings = parse_bandit_report(fixture_path)

    assert len(findings) == 2

    # Check SQL Injection finding
    sqli = findings[0]
    assert sqli.scanner == "bandit"
    assert sqli.finding_type == FindingType.SAST
    assert "B608" in sqli.rule_id
    assert sqli.severity == SeverityLevel.HIGH
    assert "CWE-89" in sqli.cwe_ids
    assert sqli.file_path == "target_repo/app.py"
    assert sqli.start_line == 28

    # Check Command Injection finding
    cmdi = findings[1]
    assert cmdi.scanner == "bandit"
    assert "B602" in cmdi.rule_id
    assert "CWE-78" in cmdi.cwe_ids
    assert cmdi.start_line == 49


def test_parse_empty_bandit_report():
    findings = parse_bandit_report({"results": []})
    assert len(findings) == 0
