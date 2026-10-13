from pathlib import Path
from agent_engine.tools.container_vuln_parser import parse_container_vuln_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_container_vuln_fixture():
    fixture_path = Path("tests/fixtures/container_vuln_findings.json")
    findings = parse_container_vuln_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "grype"
    assert f.finding_type == FindingType.SCA
    assert f.package_name == "libnghttp2-14"
    assert f.installed_version == "1.52.0-1"
    assert f.fixed_version == "1.58.0-1"
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "CVE-2023-44487"
    assert f.cvss_score == 7.5


def test_parse_container_vuln_empty():
    assert parse_container_vuln_report("{}") == []
