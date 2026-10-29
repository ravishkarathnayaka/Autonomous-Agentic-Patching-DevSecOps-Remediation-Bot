from pathlib import Path
from agent_engine.tools.semgrep_supply_chain_parser import parse_semgrep_supply_chain_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_semgrep_supply_chain_report():
    fixture_path = Path(__file__).parent / "fixtures" / "semgrep_supply_chain_findings.json"
    findings = parse_semgrep_supply_chain_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "semgrep-supply-chain"
    assert f.finding_type == FindingType.SCA
    assert f.severity == SeverityLevel.CRITICAL
    assert f.package_name == "urllib3"
    assert f.installed_version == "1.26.17"
    assert f.fixed_version == "1.26.18"
    assert f.cvss_score == 9.1
