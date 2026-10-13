from pathlib import Path
from agent_engine.tools.brakeman_parser import parse_brakeman_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_brakeman_report_fixture():
    fixture_path = Path("tests/fixtures/brakeman_findings.json")
    findings = parse_brakeman_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "brakeman"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "SQL"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-89" in f.cwe_ids
    assert f.file_path == "app/models/user.rb"
    assert f.start_line == 15


def test_parse_brakeman_empty():
    assert parse_brakeman_report("{}") == []
