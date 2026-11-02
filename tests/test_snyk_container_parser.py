from pathlib import Path
from agent_engine.tools.snyk_container_parser import parse_snyk_container_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_snyk_container_report():
    fixture_path = Path(__file__).parent / "fixtures" / "snyk_container_findings.json"
    findings = parse_snyk_container_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "snyk-container"
    assert f.finding_type == FindingType.CONTAINER
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "CVE-2023-0286"
    assert f.cvss_score == 7.5
    assert "openssl==1.1.1n-0+deb11u4" in f.vulnerable_code
