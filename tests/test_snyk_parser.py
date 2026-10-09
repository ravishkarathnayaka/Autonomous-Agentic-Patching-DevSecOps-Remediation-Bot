from pathlib import Path
from agent_engine.tools.snyk_parser import parse_snyk_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_snyk_report_from_file():
    fixture_path = Path("tests/fixtures/snyk_findings.json")
    findings = parse_snyk_report(fixture_path)

    assert len(findings) == 2

    # Finding 1: Flask CVE-2023-30861
    f1 = findings[0]
    assert f1.scanner == "snyk"
    assert f1.finding_type == FindingType.SCA
    assert f1.package_name == "Flask"
    assert f1.installed_version == "2.2.0"
    assert f1.fixed_version == "2.2.5"
    assert f1.severity == SeverityLevel.HIGH
    assert f1.rule_id == "CVE-2023-30861"
    assert "CWE-384" in f1.cwe_ids
    assert f1.cvss_score == 7.5

    # Finding 2: Werkzeug CVE-2023-25577
    f2 = findings[1]
    assert f2.package_name == "Werkzeug"
    assert f2.severity == SeverityLevel.MEDIUM
    assert f2.fixed_version == "2.2.3"
    assert f2.cvss_score == 6.5


def test_parse_snyk_report_empty():
    assert parse_snyk_report("{}") == []
