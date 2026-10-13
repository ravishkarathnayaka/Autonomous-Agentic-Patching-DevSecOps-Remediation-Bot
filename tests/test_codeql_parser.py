from pathlib import Path
from agent_engine.tools.codeql_parser import parse_codeql_sarif
from agent_engine.state import FindingType, SeverityLevel


def test_parse_codeql_sarif_fixture():
    fixture_path = Path("tests/fixtures/codeql_findings.sarif")
    findings = parse_codeql_sarif(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "codeql"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "py/sql-injection"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-89" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 28
    assert f.end_line == 29
    assert f.cvss_score == 8.8


def test_parse_codeql_empty():
    assert parse_codeql_sarif("{}") == []
