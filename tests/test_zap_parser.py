import json
from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.zap_parser import parse_zap_report, _map_zap_riskcode


def test_zap_parser_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "zap_findings.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = parse_zap_report(data)
    assert len(findings) == 2

    sqli = next(f for f in findings if f.rule_id == "40018")
    assert sqli.scanner == "owasp_zap"
    assert sqli.finding_type == FindingType.DAST
    assert sqli.severity == SeverityLevel.HIGH
    assert "CWE-89" in sqli.cwe_ids
    assert "SQL Injection" in sqli.title
    assert "http://localhost:8000/api/users?id=1" in sqli.file_path
    assert "attack vector" in sqli.vulnerable_code.lower()

    xss = next(f for f in findings if f.rule_id == "40012")
    assert xss.severity == SeverityLevel.MEDIUM
    assert "CWE-79" in xss.cwe_ids


def test_zap_riskcode_mapping():
    assert _map_zap_riskcode("3") == SeverityLevel.HIGH
    assert _map_zap_riskcode("2") == SeverityLevel.MEDIUM
    assert _map_zap_riskcode("1") == SeverityLevel.LOW
    assert _map_zap_riskcode("0") == SeverityLevel.INFO
    assert _map_zap_riskcode("invalid", "High severity alert") == SeverityLevel.HIGH
