from pathlib import Path
from agent_engine.tools.sonar_hotspots_parser import parse_sonar_hotspots_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_sonar_hotspots_report():
    fixture_path = Path(__file__).parent / "fixtures" / "sonar_hotspots_findings.json"
    findings = parse_sonar_hotspots_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "sonarqube-hotspots"
    assert f.finding_type == FindingType.SAST
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "sonar.hotspot.insecure-cookie"
    assert "CWE-614" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 191
