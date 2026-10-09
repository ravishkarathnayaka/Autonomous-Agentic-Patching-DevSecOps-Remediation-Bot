"""Unit tests for pip-audit SCA parser."""

from pathlib import Path
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.pip_audit_parser import parse_pip_audit_report


def test_parse_pip_audit_report():
    fixture = Path(__file__).parent / "fixtures" / "pip_audit_findings.json"
    findings = parse_pip_audit_report(fixture)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "pip-audit"
    assert f.finding_type == FindingType.SCA
    assert f.rule_id == "CVE-2023-30861"
    assert f.package_name == "flask"
    assert f.installed_version == "2.2.0"
    assert f.fixed_version == "2.2.5"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-1395" in f.cwe_ids


def test_parse_empty_pip_audit():
    findings = parse_pip_audit_report({"dependencies": []})
    assert len(findings) == 0
