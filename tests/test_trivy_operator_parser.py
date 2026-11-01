from pathlib import Path
from agent_engine.tools.trivy_operator_parser import parse_trivy_operator_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_trivy_operator_report():
    fixture_path = Path(__file__).parent / "fixtures" / "trivy_operator_findings.json"
    findings = parse_trivy_operator_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "trivy-operator"
    assert f.finding_type == FindingType.CONTAINER
    assert f.severity == SeverityLevel.CRITICAL
    assert f.rule_id == "CVE-2023-38545"
    assert f.cvss_score == 9.8
    assert "payment-api-deployment-7f99" in f.file_path
    assert "7.88.1-10+deb12u4" in f.vulnerable_code
