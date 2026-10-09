"""Unit tests for Checkov IaC parser."""

from pathlib import Path
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.checkov_parser import parse_checkov_report


def test_parse_checkov_report():
    fixture = Path(__file__).parent / "fixtures" / "checkov_findings.json"
    findings = parse_checkov_report(fixture)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "checkov"
    assert f.finding_type == FindingType.SAST
    assert "CKV_DOCKER_3" in f.rule_id
    assert f.severity == SeverityLevel.HIGH
    assert f.file_path == "docker/sandbox.Dockerfile"
    assert "Ensure that a user for the container has been created" in f.title


def test_parse_empty_checkov():
    findings = parse_checkov_report({"results": {"failed_checks": []}})
    assert len(findings) == 0
