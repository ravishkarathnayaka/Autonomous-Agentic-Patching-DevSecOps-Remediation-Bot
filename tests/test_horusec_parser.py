from pathlib import Path
from agent_engine.tools.horusec_parser import parse_horusec_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_horusec_report_fixture():
    fixture_path = Path("tests/fixtures/horusec_findings.json")
    findings = parse_horusec_report(fixture_path)

    assert len(findings) >= 1
    f = findings[0]
    assert f.scanner == "horusec"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "HS-PYTHON-1"
    assert f.severity == SeverityLevel.CRITICAL
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 52


def test_parse_horusec_empty():
    assert parse_horusec_report("{}") == []
