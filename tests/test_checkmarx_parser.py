from pathlib import Path
from agent_engine.tools.checkmarx_parser import parse_checkmarx_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_checkmarx_report():
    fixture_path = Path(__file__).parent / "fixtures" / "checkmarx_findings.json"
    findings = parse_checkmarx_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "checkmarx"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "Cx-10023"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-79" in f.cwe_ids
    assert f.start_line == 42
    assert "render_template_string" in f.vulnerable_code
