from pathlib import Path
from agent_engine.tools.kics_parser import parse_kics_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_kics_report_fixture():
    fixture_path = Path("tests/fixtures/kics_findings.json")
    findings = parse_kics_report(fixture_path)

    assert len(findings) >= 1
    f = findings[0]
    assert f.scanner == "kics"
    assert f.finding_type == FindingType.IAC
    assert f.rule_id == "fd54f200-402c-4333-a5a4-36ef6709af2f"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-250" in f.cwe_ids
    assert f.file_path == "docker/sandbox.Dockerfile"
    assert f.start_line == 3


def test_parse_kics_empty():
    assert parse_kics_report("{}") == []
