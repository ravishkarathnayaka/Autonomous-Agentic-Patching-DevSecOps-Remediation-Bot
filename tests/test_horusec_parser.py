import json
from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.horusec_parser import parse_horusec_report, _map_horusec_severity


def test_horusec_parser_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "horusec_findings.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = parse_horusec_report(data)
    assert len(findings) == 2

    sqli = next(f for f in findings if f.rule_id == "HS-PYTHON-1")
    assert sqli.scanner == "horusec"
    assert sqli.finding_type == FindingType.SAST
    assert sqli.severity == SeverityLevel.CRITICAL
    assert "CWE-89" in sqli.cwe_ids
    assert sqli.file_path == "target_repo/app.py"
    assert sqli.start_line == 25
    assert "cursor.execute" in sqli.vulnerable_code

    cmd_inj = next(f for f in findings if f.rule_id == "HS-PYTHON-14")
    assert cmd_inj.severity == SeverityLevel.HIGH
    assert "CWE-78" in cmd_inj.cwe_ids
    assert cmd_inj.start_line == 40


def test_horusec_severity_mapping():
    assert _map_horusec_severity("CRITICAL") == SeverityLevel.CRITICAL
    assert _map_horusec_severity("HIGH") == SeverityLevel.HIGH
    assert _map_horusec_severity("MEDIUM") == SeverityLevel.MEDIUM
    assert _map_horusec_severity("LOW") == SeverityLevel.LOW
    assert _map_horusec_severity("INFO") == SeverityLevel.INFO
