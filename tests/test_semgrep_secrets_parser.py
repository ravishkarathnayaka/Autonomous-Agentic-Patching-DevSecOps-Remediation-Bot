from pathlib import Path
from agent_engine.tools.semgrep_secrets_parser import parse_semgrep_secrets_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_semgrep_secrets_report():
    fixture_path = Path(__file__).parent / "fixtures" / "semgrep_secrets_findings.json"
    findings = parse_semgrep_secrets_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "semgrep-secrets"
    assert f.finding_type == FindingType.SECRET
    assert f.severity == SeverityLevel.CRITICAL
    assert "CWE-798" in f.cwe_ids
    assert f.start_line == 130
    assert "sk_live" in f.vulnerable_code
