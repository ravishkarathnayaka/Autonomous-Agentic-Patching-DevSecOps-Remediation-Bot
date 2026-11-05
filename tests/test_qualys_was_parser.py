from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.qualys_was_parser import parse_qualys_was_report


def test_parse_qualys_was_report():
    fixture_path = Path("tests/fixtures/qualys_was_findings.json")
    findings = parse_qualys_was_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "qualys"
    assert f1.finding_type == FindingType.DAST
    assert f1.rule_id == "QID-150004"
    assert f1.severity == SeverityLevel.HIGH
    assert "CWE-79" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "QID-150081"
    assert f2.severity == SeverityLevel.CRITICAL
    assert "CWE-89" in f2.cwe_ids
