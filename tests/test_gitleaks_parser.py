"""Unit tests for Gitleaks secrets scanner parser."""

from pathlib import Path
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.gitleaks_parser import parse_gitleaks_report


def test_parse_gitleaks_report():
    fixture = Path(__file__).parent / "fixtures" / "gitleaks_findings.json"
    findings = parse_gitleaks_report(fixture)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "gitleaks"
    assert f.finding_type == FindingType.SAST
    assert "aws-access-key-id" in f.rule_id
    assert f.severity == SeverityLevel.CRITICAL
    assert "CWE-798" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 12
    assert "AKIAIOSFODNN7EXAMPLE" in f.vulnerable_code


def test_parse_empty_gitleaks_report():
    findings = parse_gitleaks_report([])
    assert len(findings) == 0
