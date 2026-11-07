from pathlib import Path
from agent_engine.tools.orca_parser import parse_orca_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_orca_report():
    fixture_path = Path("tests/fixtures/orca_findings.json")
    findings = parse_orca_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.CLOUD
    assert f1.scanner == "orca"
    assert f1.rule_id == "CVE-2023-44487"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.cvss_score == 9.4
    assert "CWE-400" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "ORCA-IAM-022"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.cvss_score == 7.6


def test_parse_orca_empty():
    findings = parse_orca_report({})
    assert len(findings) == 0
