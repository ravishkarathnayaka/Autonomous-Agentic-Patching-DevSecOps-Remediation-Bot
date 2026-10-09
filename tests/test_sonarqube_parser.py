from pathlib import Path
from agent_engine.tools.sonarqube_parser import parse_sonarqube_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_sonarqube_report_from_file():
    fixture_path = Path("tests/fixtures/sonarqube_findings.json")
    findings = parse_sonarqube_report(fixture_path)

    assert len(findings) == 2

    # Issue 1: S2077 SQL Injection
    f1 = findings[0]
    assert f1.scanner == "sonarqube"
    assert f1.finding_type == FindingType.SAST
    assert f1.rule_id == "python:S2077"
    assert f1.severity == SeverityLevel.HIGH  # CRITICAL in Sonar maps to HIGH
    assert f1.file_path == "target_repo/app.py"
    assert f1.start_line == 28
    assert "CWE-89" in f1.cwe_ids

    # Issue 2: S2083 Path Traversal
    f2 = findings[1]
    assert f2.rule_id == "python:S2083"
    assert f2.severity == SeverityLevel.MEDIUM  # MAJOR maps to MEDIUM
    assert f2.file_path == "target_repo/app.py"
    assert f2.start_line == 42
    assert "CWE-22" in f2.cwe_ids


def test_parse_sonarqube_empty():
    assert parse_sonarqube_report("{}") == []
