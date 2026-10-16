from pathlib import Path
from agent_engine.tools.govulncheck_parser import parse_govulncheck_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_govulncheck_fixture():
    fixture_path = Path("tests/fixtures/govulncheck_findings.json")
    findings = parse_govulncheck_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "govulncheck"
    assert f.finding_type == FindingType.SCA
    assert f.rule_id == "CVE-2023-24538"
    assert f.package_name == "golang.org/x/net"
    assert f.fixed_version == "v0.7.0"
    assert f.severity == SeverityLevel.HIGH


def test_parse_govulncheck_empty():
    assert parse_govulncheck_report("{}") == []
