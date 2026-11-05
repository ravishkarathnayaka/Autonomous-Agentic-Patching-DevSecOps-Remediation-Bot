from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.linear_formatter import LinearTicketFormatter


def test_linear_formatter_critical():
    finding = Finding(
        id="acunetix-cwe235-01",
        scanner="acunetix",
        finding_type=FindingType.DAST,
        rule_id="CWE-235",
        title="HTTP Parameter Pollution",
        description="Duplicate parameter handling flaws enable transaction forgery",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-235"],
        file_path="target_repo/app.py",
        start_line=500,
        vulnerable_code="recipient = request.args.get('recipient')",
    )

    payload = LinearTicketFormatter.format_issue_payload(
        finding,
        team_id="team_sec_lead",
        patch_summary="Patch synthesized with getlist and multiplicity verification.",
    )

    assert payload["teamId"] == "team_sec_lead"
    assert "[CRITICAL] CWE-235" in payload["title"]
    assert payload["priority"] == 1  # Urgent for CRITICAL
    assert "bot-remediated" in payload["labels"]
    assert "acunetix" in payload["labels"]
    assert "recipient = request.args.get('recipient')" in payload["description"]
    assert "Patch synthesized with getlist" in payload["description"]


def test_linear_formatter_medium():
    finding = Finding(
        id="semgrep-xxe-02",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-611",
        title="XML External Entity in SVG",
        description="DTD resolution allows file disclosure",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-611"],
        file_path="target_repo/app.py",
    )

    payload = LinearTicketFormatter.format_issue_payload(finding)
    assert payload["priority"] == 3  # Medium
