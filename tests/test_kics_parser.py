import json
from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.kics_parser import parse_kics_report, _map_kics_severity


def test_kics_parser_fixture():
    fixture_path = Path(__file__).parent / "fixtures" / "kics_findings.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    findings = parse_kics_report(data)
    assert len(findings) == 2

    s3 = next(f for f in findings if f.file_path == "terraform/s3.tf")
    assert s3.scanner == "kics"
    assert s3.finding_type == FindingType.IAC
    assert s3.severity == SeverityLevel.HIGH
    assert "CWE-311" in s3.cwe_ids
    assert s3.start_line == 14
    assert "[Terraform]" in s3.title

    docker = next(f for f in findings if f.file_path == "Dockerfile")
    assert docker.severity == SeverityLevel.MEDIUM
    assert "CWE-250" in docker.cwe_ids
    assert docker.start_line == 1


def test_kics_severity_mapping():
    assert _map_kics_severity("HIGH") == SeverityLevel.HIGH
    assert _map_kics_severity("MEDIUM") == SeverityLevel.MEDIUM
    assert _map_kics_severity("LOW") == SeverityLevel.LOW
    assert _map_kics_severity("INFO") == SeverityLevel.INFO
