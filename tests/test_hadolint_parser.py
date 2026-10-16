from pathlib import Path
from agent_engine.tools.hadolint_parser import parse_hadolint_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_hadolint_fixture():
    fixture_path = Path("tests/fixtures/hadolint_findings.json")
    findings = parse_hadolint_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "hadolint"
    assert f.finding_type == FindingType.IAC
    assert f.rule_id == "DL3002"
    assert f.severity == SeverityLevel.MEDIUM
    assert "CWE-250" in f.cwe_ids
    assert f.file_path == "docker/sandbox.Dockerfile"
    assert f.start_line == 15


def test_parse_hadolint_empty():
    assert parse_hadolint_report([]) == []
