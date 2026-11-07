from pathlib import Path
from agent_engine.tools.mend_bolt_parser import parse_mend_bolt_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_mend_bolt_report():
    fixture_path = Path("tests/fixtures/mend_bolt_findings.json")
    findings = parse_mend_bolt_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.finding_type == FindingType.SCA
    assert f1.scanner == "mend-bolt"
    assert f1.rule_id == "CVE-2022-21699"
    assert f1.severity == SeverityLevel.HIGH
    assert f1.package_name == "ipython"
    assert f1.fixed_version == "7.31.1"

    f2 = findings[1]
    assert f2.rule_id == "CVE-2023-32681"
    assert f2.severity == SeverityLevel.CRITICAL
    assert f2.cvss_score == 9.1
    assert f2.package_name == "requests"


def test_parse_mend_bolt_empty():
    findings = parse_mend_bolt_report({})
    assert len(findings) == 0
