from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.acunetix_parser import parse_acunetix_report


def test_parse_acunetix_report():
    fixture_path = Path("tests/fixtures/acunetix_findings.json")
    findings = parse_acunetix_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "acunetix"
    assert f1.finding_type == FindingType.DAST
    assert f1.rule_id == "Server-Side Request Forgery"
    assert f1.severity == SeverityLevel.CRITICAL
    assert "CWE-918" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "Directory Traversal"
    assert f2.severity == SeverityLevel.HIGH
    assert "CWE-22" in f2.cwe_ids
