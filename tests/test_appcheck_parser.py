from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.appcheck_parser import parse_appcheck_report


def test_parse_appcheck_report():
    fixture_path = Path("tests/fixtures/appcheck_findings.json")
    findings = parse_appcheck_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "appcheck"
    assert f1.finding_type == FindingType.DAST
    assert f1.rule_id == "SQL Injection"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.cvss_score == 9.4
    assert "CWE-89" in f1.cwe_ids
    assert "category" in f1.title

    f2 = findings[1]
    assert f2.rule_id == "Cross-Site Scripting (Reflected)"
    assert f2.severity == SeverityLevel.MEDIUM
    assert f2.cvss_score == 6.1
    assert "CWE-79" in f2.cwe_ids
