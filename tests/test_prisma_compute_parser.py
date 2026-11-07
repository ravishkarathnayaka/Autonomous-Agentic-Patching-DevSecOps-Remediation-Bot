from pathlib import Path
from agent_engine.tools.prisma_compute_parser import parse_prisma_compute_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_prisma_compute_report():
    fixture_path = Path("tests/fixtures/prisma_compute_findings.json")
    findings = parse_prisma_compute_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.CONTAINER
    assert f1.scanner == "prisma-compute"
    assert f1.rule_id == "CVE-2023-38545"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.cvss_score == 9.8
    assert f1.package_name == "curl"
    assert "CWE-122" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "CVE-2023-4911"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.package_name == "glibc"


def test_parse_prisma_compute_empty():
    findings = parse_prisma_compute_report({})
    assert len(findings) == 0
