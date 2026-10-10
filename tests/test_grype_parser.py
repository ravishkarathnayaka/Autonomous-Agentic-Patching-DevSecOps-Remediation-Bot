import json
from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.grype_parser import parse_grype_report, _map_grype_severity


def test_grype_parser_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "grype_findings.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = parse_grype_report(data)
    assert len(findings) == 1

    f = findings[0]
    assert f.scanner == "grype"
    assert f.finding_type == FindingType.CONTAINER
    assert f.rule_id == "CVE-2023-32681"
    assert f.package_name == "requests"
    assert f.installed_version == "2.30.0"
    assert f.fixed_version == "2.31.0"
    assert f.severity == SeverityLevel.MEDIUM
    assert f.cvss_score == 6.1
    assert "CWE-200" in f.cwe_ids
    assert f.file_path == "/app/requirements.txt"


def test_grype_severity_mapping():
    assert _map_grype_severity("CRITICAL") == SeverityLevel.CRITICAL
    assert _map_grype_severity("HIGH") == SeverityLevel.HIGH
    assert _map_grype_severity("Medium") == SeverityLevel.MEDIUM
    assert _map_grype_severity("Low") == SeverityLevel.LOW
    assert _map_grype_severity("Negligible") == SeverityLevel.INFO
