from pathlib import Path
from agent_engine.tools.prisma_cloud_parser import parse_prisma_cloud_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_prisma_cloud_report():
    fixture_path = Path(__file__).parent / "fixtures" / "prisma_cloud_findings.json"
    findings = parse_prisma_cloud_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "prisma-cloud"
    assert f.finding_type == FindingType.CONTAINER
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "CVE-2023-38039"
    assert f.cvss_score == 7.5
    assert "curl==7.88.1-10" in f.vulnerable_code
