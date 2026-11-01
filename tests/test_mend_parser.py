from pathlib import Path
from agent_engine.tools.mend_parser import parse_mend_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_mend_report():
    fixture_path = Path(__file__).parent / "fixtures" / "mend_findings.json"
    findings = parse_mend_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "mend"
    assert f.finding_type == FindingType.SCA
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "CVE-2023-43804"
    assert f.cvss_score == 8.1
    assert "urllib3==1.26.17" in f.vulnerable_code
