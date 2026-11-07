from pathlib import Path
from agent_engine.tools.deepsource_parser import parse_deepsource_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_deepsource_report():
    fixture_path = Path("tests/fixtures/deepsource_findings.json")
    findings = parse_deepsource_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.SAST
    assert f1.scanner == "deepsource"
    assert f1.rule_id == "PTC-W1004"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.start_line == 15
    assert "CWE-89" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "PTC-W1009"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.start_line == 42
    assert "CWE-377" in f2.cwe_ids


def test_parse_deepsource_empty():
    findings = parse_deepsource_report({})
    assert len(findings) == 0
