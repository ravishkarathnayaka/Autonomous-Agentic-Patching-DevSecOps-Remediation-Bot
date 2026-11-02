from pathlib import Path
from agent_engine.tools.gitlab_dependency_parser import parse_gitlab_dependency_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_gitlab_dependency_report():
    fixture_path = Path(__file__).parent / "fixtures" / "gitlab_dependency_findings.json"
    findings = parse_gitlab_dependency_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "gitlab-dependency-scanning"
    assert f.finding_type == FindingType.SCA
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "CVE-2023-32681"
    assert "requests==2.28.1" in f.vulnerable_code
