from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.insightappsec_parser import parse_insightappsec_report


def test_parse_insightappsec_report():
    fixture_path = Path("tests/fixtures/insightappsec_findings.json")
    findings = parse_insightappsec_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "insightappsec"
    assert f1.finding_type == FindingType.DAST
    assert f1.rule_id == "Path Traversal"
    assert f1.severity == SeverityLevel.HIGH
    assert "CWE-59" in f1.cwe_ids
    assert "filename" in f1.title

    f2 = findings[1]
    assert f2.rule_id == "SQL Injection"
    assert f2.severity == SeverityLevel.CRITICAL
    assert "CWE-89" in f2.cwe_ids
