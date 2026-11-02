import pytest
from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.jira_formatter import JiraTicketFormatter


def test_jira_formatter_payload():
    finding = Finding(
        id="contrast-sqli-01",
        scanner="contrast",
        finding_type=FindingType.SAST,
        rule_id="CWE-89",
        title="SQL Injection in account search",
        description="Query concatenation observed in live telemetry",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-89"],
        file_path="app/controllers/account.py",
    )

    payload = JiraTicketFormatter.format_issue_payload(
        finding=finding,
        project_key="APSEC",
        issue_type="Vulnerability",
        additional_labels=["sprint-42"],
        patch_summary="Patch successfully generated and verified in sandbox.",
    )

    fields = payload["fields"]
    assert fields["project"]["key"] == "APSEC"
    assert fields["issuetype"]["name"] == "Vulnerability"
    assert fields["priority"]["name"] == "Highest"
    assert "[CRITICAL] CWE-89:" in fields["summary"]
    assert "autonomous-sec-bot" in fields["labels"]
    assert "sprint-42" in fields["labels"]
    assert "contrast" in fields["labels"]
