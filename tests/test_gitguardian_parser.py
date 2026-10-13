from pathlib import Path
from agent_engine.tools.gitguardian_parser import parse_gitguardian_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_gitguardian_report_fixture():
    fixture_path = Path("tests/fixtures/gitguardian_findings.json")
    findings = parse_gitguardian_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "gitguardian"
    assert f.finding_type == FindingType.SECRET
    assert f.rule_id == "stripe_secret_key"
    assert f.severity == SeverityLevel.CRITICAL
    assert "CWE-798" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 18


def test_parse_gitguardian_empty():
    assert parse_gitguardian_report("{}") == []
