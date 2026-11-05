from pathlib import Path
from agent_engine.tools.lacework_parser import parse_lacework_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_lacework_report():
    fixture_path = Path("tests/fixtures/lacework_findings.json")
    findings = parse_lacework_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.CONTAINER
    assert f1.severity == SeverityLevel.HIGH
    assert f1.rule_id == "CVE-2023-4807"
    assert "openssl" in f1.title
    assert "CWE-327" in f1.cwe_ids

    f2 = findings[1]
    assert f2.finding_type == FindingType.CONTAINER
    assert f2.severity == SeverityLevel.CRITICAL
    assert f2.rule_id == "CVE-2023-38039"
    assert "curl" in f2.title
    assert "CWE-400" in f2.cwe_ids


def test_parse_lacework_empty():
    findings = parse_lacework_report({})
    assert len(findings) == 0
