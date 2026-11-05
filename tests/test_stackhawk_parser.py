from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.stackhawk_parser import parse_stackhawk_report


def test_parse_stackhawk_report():
    fixture_path = Path("tests/fixtures/stackhawk_findings.json")
    findings = parse_stackhawk_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "stackhawk"
    assert f1.finding_type == FindingType.DAST
    assert f1.rule_id == "HAWK-40018"
    assert f1.severity == SeverityLevel.HIGH
    assert "CWE-89" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "HAWK-10038"
    assert f2.severity == SeverityLevel.MEDIUM
    assert "CWE-693" in f2.cwe_ids
