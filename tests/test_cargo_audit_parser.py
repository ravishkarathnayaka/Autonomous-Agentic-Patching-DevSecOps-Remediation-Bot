from pathlib import Path
from agent_engine.tools.cargo_audit_parser import parse_cargo_audit_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_cargo_audit_fixture():
    fixture_path = Path("tests/fixtures/cargo_audit_findings.json")
    findings = parse_cargo_audit_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "cargo-audit"
    assert f.finding_type == FindingType.SCA
    assert f.rule_id == "RUSTSEC-2023-0001"
    assert f.package_name == "hyper"
    assert f.installed_version == "0.14.25"
    assert f.fixed_version == ">= 0.14.27"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-416" in f.cwe_ids


def test_parse_cargo_audit_empty():
    assert parse_cargo_audit_report("{}") == []
