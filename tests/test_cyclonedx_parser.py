from pathlib import Path
from agent_engine.tools.cyclonedx_parser import parse_cyclonedx_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_cyclonedx_report():
    fixture_path = Path(__file__).parent / "fixtures" / "cyclonedx_findings.json"
    findings = parse_cyclonedx_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "cyclonedx"
    assert f.finding_type == FindingType.SCA
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "CVE-2023-30861"
    assert "CWE-384" in f.cwe_ids
    assert "pkg:pypi/flask@2.2.0" in f.vulnerable_code
