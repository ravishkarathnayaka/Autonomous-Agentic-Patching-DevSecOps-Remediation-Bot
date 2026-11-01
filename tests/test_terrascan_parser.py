from pathlib import Path
from agent_engine.tools.terrascan_parser import parse_terrascan_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_terrascan_report():
    fixture_path = Path(__file__).parent / "fixtures" / "terrascan_findings.json"
    findings = parse_terrascan_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "terrascan"
    assert f.finding_type == FindingType.IAC
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "AC_AWS_0207"
    assert f.file_path == "terraform/storage.tf"
    assert f.start_line == 14
    assert "aws_s3_bucket.app_bucket" in f.vulnerable_code
