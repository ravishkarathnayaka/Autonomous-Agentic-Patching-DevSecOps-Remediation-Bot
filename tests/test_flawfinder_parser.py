from pathlib import Path
from agent_engine.tools.flawfinder_parser import parse_flawfinder_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_flawfinder_fixture():
    fixture_path = Path("tests/fixtures/flawfinder_findings.json")
    findings = parse_flawfinder_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "flawfinder"
    assert f.finding_type == FindingType.SAST
    assert f.severity == SeverityLevel.CRITICAL
    assert "CWE-120" in f.cwe_ids
    assert f.file_path == "target_repo/native_crypto.c"
    assert f.start_line == 45


def test_parse_flawfinder_empty():
    assert parse_flawfinder_report("[]") == []
