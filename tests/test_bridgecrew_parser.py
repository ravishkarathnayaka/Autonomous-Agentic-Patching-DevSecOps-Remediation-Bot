from pathlib import Path
from agent_engine.tools.bridgecrew_parser import parse_bridgecrew_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_bridgecrew_report():
    fixture_path = Path("tests/fixtures/bridgecrew_findings.json")
    findings = parse_bridgecrew_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.IAC
    assert f1.scanner == "bridgecrew"
    assert f1.rule_id == "BC_AWS_S3_1"
    assert f1.severity == SeverityLevel.MEDIUM
    assert f1.file_path == "terraform/s3.tf"
    assert f1.start_line == 10
    assert f1.end_line == 22
    assert "access logging" in f1.title

    f2 = findings[1]
    assert f2.finding_type == FindingType.IAC
    assert f2.rule_id == "BC_AWS_IAM_45"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.file_path == "terraform/iam.tf"
    assert f2.start_line == 35


def test_parse_bridgecrew_empty():
    findings = parse_bridgecrew_report({})
    assert len(findings) == 0
