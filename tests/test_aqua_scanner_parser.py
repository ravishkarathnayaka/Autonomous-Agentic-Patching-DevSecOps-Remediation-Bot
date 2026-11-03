from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.aqua_scanner_parser import parse_aqua_report


def test_parse_aqua_report():
    fixture_path = Path("tests/fixtures/aqua_findings.json")
    findings = parse_aqua_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "aqua"
    assert f1.finding_type == FindingType.CONTAINER
    assert f1.rule_id == "CVE-2023-5363"
    assert f1.severity == SeverityLevel.HIGH
    assert "CWE-326" in f1.cwe_ids
    assert "upgrade to 3.1.4-r0" in f1.description

    f2 = findings[1]
    assert f2.rule_id == "CVE-2023-44487"
    assert f2.severity == SeverityLevel.CRITICAL
