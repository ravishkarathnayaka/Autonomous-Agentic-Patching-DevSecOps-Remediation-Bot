from pathlib import Path
from agent_engine.tools.fortify_parser import parse_fortify_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_fortify_report():
    fixture_path = Path(__file__).parent / "fixtures" / "fortify_findings.json"
    findings = parse_fortify_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "fortify"
    assert f.finding_type == FindingType.SAST
    assert f.severity == SeverityLevel.CRITICAL
    assert "CWE-89" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 38
