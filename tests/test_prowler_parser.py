from pathlib import Path
from agent_engine.tools.prowler_parser import parse_prowler_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_prowler_report():
    fixture_path = Path("tests/fixtures/prowler_findings.json")
    findings = parse_prowler_report(fixture_path)

    # 3 checks in fixture: 2 FAIL, 1 PASS -> only 2 findings parsed
    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.CLOUD
    assert f1.scanner == "prowler"
    assert f1.rule_id == "s3_bucket_default_encryption"
    assert f1.severity == SeverityLevel.HIGH
    assert "encryption enabled" in f1.title
    assert "arn:aws:s3:::unencrypted-data-bucket" in f1.file_path

    f2 = findings[1]
    assert f2.rule_id == "iam_root_hardware_mfa_enabled"
    assert f2.severity == SeverityLevel.CRITICAL
    assert "MFA is enabled" in f2.title


def test_parse_prowler_empty():
    findings = parse_prowler_report([])
    assert len(findings) == 0
