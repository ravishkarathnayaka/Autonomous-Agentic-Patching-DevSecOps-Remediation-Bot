from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.jfrog_xray_parser import parse_jfrog_xray_report


def test_parse_jfrog_xray_report():
    fixture_path = Path("tests/fixtures/jfrog_xray_findings.json")
    findings = parse_jfrog_xray_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "jfrog-xray"
    assert f1.finding_type == FindingType.SCA
    assert f1.rule_id == "CVE-2020-14343"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.cvss_score == 9.8
    assert f1.package_name == "PyYAML"
    assert f1.fixed_version == "5.4"

    f2 = findings[1]
    assert f2.rule_id == "CVE-2023-43804"
    assert f2.severity == SeverityLevel.MEDIUM
    assert f2.package_name == "urllib3"
    assert f2.fixed_version == "1.26.18"
