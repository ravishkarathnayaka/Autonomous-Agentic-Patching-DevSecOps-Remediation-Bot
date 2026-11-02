from pathlib import Path
from agent_engine.tools.blackduck_parser import parse_blackduck_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_blackduck_report():
    fixture_path = Path(__file__).parent / "fixtures" / "blackduck_findings.json"
    findings = parse_blackduck_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "blackduck"
    assert f.finding_type == FindingType.SCA
    assert f.severity == SeverityLevel.CRITICAL
    assert f.rule_id == "BDSA-2023-1492"
    assert f.cvss_score == 9.8
    assert "sqlalchemy==1.4.40" in f.vulnerable_code
