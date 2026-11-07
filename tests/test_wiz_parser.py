from pathlib import Path
from agent_engine.tools.wiz_parser import parse_wiz_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_wiz_report():
    fixture_path = Path("tests/fixtures/wiz_findings.json")
    findings = parse_wiz_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.CLOUD
    assert f1.scanner == "wiz"
    assert f1.rule_id == "WIZ-RULE-001"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.cvss_score == 9.2
    assert "CWE-732" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "CVE-2023-22515"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.cvss_score == 8.8


def test_parse_wiz_empty():
    findings = parse_wiz_report({})
    assert len(findings) == 0
