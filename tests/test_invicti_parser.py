from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.invicti_parser import parse_invicti_report


def test_parse_invicti_report():
    fixture_path = Path("tests/fixtures/invicti_findings.json")
    findings = parse_invicti_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "invicti"
    assert f1.finding_type == FindingType.DAST
    assert f1.rule_id == "XPath Injection"
    assert f1.severity == SeverityLevel.CRITICAL
    assert "CWE-643" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "Insecure Deserialization"
    assert f2.severity == SeverityLevel.HIGH
    assert "CWE-502" in f2.cwe_ids
