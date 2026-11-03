from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.spectral_parser import parse_spectral_report


def test_parse_spectral_report():
    fixture_path = Path("tests/fixtures/spectral_findings.json")
    findings = parse_spectral_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "spectral"
    assert f1.finding_type == FindingType.SECRET
    assert f1.rule_id == "aws-access-key-id"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.file_path == "config/cloud_credentials.py"
    assert f1.start_line == 14
    assert "CWE-798" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "generic-api-key"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.start_line == 42
