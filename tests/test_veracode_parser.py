from pathlib import Path
from agent_engine.tools.veracode_parser import parse_veracode_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_veracode_report():
    fixture_path = Path(__file__).parent / "fixtures" / "veracode_findings.json"
    findings = parse_veracode_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "veracode"
    assert f.finding_type == FindingType.SAST
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-78" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 57
    assert f.cvss_score == 7.5
