from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.anchore_enterprise_parser import parse_anchore_enterprise_report


def test_parse_anchore_enterprise_report():
    fixture_path = Path("tests/fixtures/anchore_enterprise_findings.json")
    findings = parse_anchore_enterprise_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "anchore"
    assert f1.finding_type == FindingType.CONTAINER
    assert f1.rule_id == "CVE-2023-38552"
    assert f1.severity == SeverityLevel.HIGH
    assert f1.cvss_score == 7.8
    assert f1.package_name == "glibc"
    assert f1.fixed_version == "2.35-0ubuntu3.4"

    f2 = findings[1]
    assert f2.rule_id == "CVE-2023-4911"
    assert f2.severity == SeverityLevel.CRITICAL
    assert f2.cvss_score == 9.8
