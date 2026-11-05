from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.sonarcloud_parser import parse_sonarcloud_report


def test_parse_sonarcloud_report():
    fixture_path = Path("tests/fixtures/sonarcloud_findings.json")
    findings = parse_sonarcloud_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "sonarcloud"
    assert f1.finding_type == FindingType.SAST
    assert f1.rule_id == "python:S2077"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.file_path == "target_repo/app.py"
    assert f1.start_line == 68

    f2 = findings[1]
    assert f2.rule_id == "python:S5144"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.start_line == 372
