from pathlib import Path
from agent_engine.tools.github_secret_scanning_parser import parse_github_secret_scanning_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_github_secret_scanning_report():
    fixture_path = Path(__file__).parent / "fixtures" / "github_secret_scanning_findings.json"
    findings = parse_github_secret_scanning_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "github-secret-scanning"
    assert f.finding_type == FindingType.SECRET
    assert f.severity == SeverityLevel.CRITICAL
    assert "CWE-798" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 130
    assert "Stripe API Key" in f.title
