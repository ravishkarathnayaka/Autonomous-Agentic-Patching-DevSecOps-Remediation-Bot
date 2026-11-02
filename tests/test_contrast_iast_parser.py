from pathlib import Path
from agent_engine.tools.contrast_iast_parser import parse_contrast_iast_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_contrast_iast_report():
    fixture_path = Path(__file__).parent / "fixtures" / "contrast_iast_findings.json"
    findings = parse_contrast_iast_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "contrast-iast"
    assert f.finding_type == FindingType.DAST
    assert f.severity == SeverityLevel.CRITICAL
    assert "CWE-78" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 57
