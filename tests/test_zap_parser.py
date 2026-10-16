from pathlib import Path
from agent_engine.tools.zap_parser import parse_zap_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_zap_report_fixture():
    fixture_path = Path("tests/fixtures/zap_dast_findings.json")
    findings = parse_zap_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "owasp_zap"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "ZAP-10038"
    assert f.severity == SeverityLevel.MEDIUM
    assert "CWE-693" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"


def test_parse_zap_empty():
    assert parse_zap_report("{}") == []
