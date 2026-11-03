import pytest
from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.gitlab_issue_formatter import GitlabIssueFormatter


def test_gitlab_formatter_payload():
    finding = Finding(
        id="semgrep-sqli-gitlab",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-89",
        title="SQL Injection in user search",
        description="Dynamic string formatting into raw SQL query",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-89"],
        file_path="target_repo/app.py",
        start_line=68,
    )

    payload = GitlabIssueFormatter.format_issue_payload(
        finding=finding,
        confidential=True,
        additional_labels=["team::platform", "workflow::triage"],
        patch_summary="Patch synthesized and sandbox verified.",
    )

    assert "[CRITICAL] Security: CWE-89" in payload["title"]
    assert payload["confidential"] is True
    assert payload["weight"] == 5
    assert "severity::critical" in payload["labels"]
    assert "team::platform" in payload["labels"]
    assert "autonomous-remediation" in payload["labels"]
    assert "### Autonomous Remediation" in payload["description"]
