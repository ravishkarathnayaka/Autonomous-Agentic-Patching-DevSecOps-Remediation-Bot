from pathlib import Path
from agent_engine.tools.trufflehog_parser import parse_trufflehog_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_trufflehog_fixture():
    fixture_path = Path("tests/fixtures/trufflehog_v3_findings.json")
    findings = parse_trufflehog_report(fixture_path)

    assert len(findings) == 2
    f1 = findings[0]
    assert f1.scanner == "trufflehog"
    assert f1.finding_type == FindingType.SECRET
    assert f1.rule_id == "AWS"
    assert f1.severity == SeverityLevel.CRITICAL
    assert "CWE-798" in f1.cwe_ids
    assert f1.start_line == 15

    f2 = findings[1]
    assert f2.rule_id == "Slack"
    assert f2.severity == SeverityLevel.HIGH


def test_parse_trufflehog_empty():
    assert parse_trufflehog_report("") == []
