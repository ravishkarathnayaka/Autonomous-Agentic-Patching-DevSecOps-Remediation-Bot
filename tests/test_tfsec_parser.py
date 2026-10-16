from pathlib import Path
from agent_engine.tools.tfsec_parser import parse_tfsec_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_tfsec_fixture():
    fixture_path = Path("tests/fixtures/tfsec_findings.json")
    findings = parse_tfsec_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "tfsec"
    assert f.finding_type == FindingType.IAC
    assert f.rule_id == "aws-s3-enable-bucket-encryption"
    assert f.severity == SeverityLevel.HIGH
    assert f.file_path == "terraform/storage.tf"
    assert f.start_line == 12


def test_parse_tfsec_empty():
    assert parse_tfsec_report("{}") == []
