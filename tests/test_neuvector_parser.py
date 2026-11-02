from pathlib import Path
from agent_engine.tools.neuvector_parser import parse_neuvector_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_neuvector_report():
    fixture_path = Path(__file__).parent / "fixtures" / "neuvector_findings.json"
    findings = parse_neuvector_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "neuvector"
    assert f.finding_type == FindingType.CONTAINER
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "CVE-2023-44487"
    assert f.cvss_score == 7.5
    assert "nghttp2==1.43.0-1" in f.vulnerable_code
