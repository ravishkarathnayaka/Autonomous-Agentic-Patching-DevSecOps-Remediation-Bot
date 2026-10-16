"""
Unit tests for SlackBlockKitFormatter.
"""

from agent_engine.tools.slack_blockkit import SlackBlockKitFormatter


def test_format_finding_alert_with_pr():
    payload = SlackBlockKitFormatter.format_finding_alert(
        vuln_id="SEC-001",
        severity="CRITICAL",
        cwe="CWE-89",
        file_path="target_repo/app.py",
        line=42,
        description="SQL injection vulnerability in query parameter.",
        remediation_branch="remediate/cwe-89-sec-001",
        pr_url="https://github.com/org/repo/pull/12"
    )

    assert "blocks" in payload
    blocks = payload["blocks"]
    assert len(blocks) == 5  # header, fields, desc, context, actions

    # Check header
    assert blocks[0]["type"] == "header"
    assert "SEC-001" in blocks[0]["text"]["text"]

    # Check fields
    fields_block = blocks[1]
    assert fields_block["type"] == "section"
    texts = [f["text"] for f in fields_block["fields"]]
    assert any("CRITICAL" in t for t in texts)
    assert any("CWE-89" in t for t in texts)

    # Check actions button
    action_block = blocks[4]
    assert action_block["type"] == "actions"
    assert action_block["elements"][0]["url"] == "https://github.com/org/repo/pull/12"


def test_format_scan_summary():
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 2, "LOW": 5}
    payload = SlackBlockKitFormatter.format_scan_summary(
        repository="enterprise/core-api",
        total_scanned=45,
        findings_by_severity=counts,
        duration_seconds=1.45
    )

    blocks = payload["blocks"]
    assert len(blocks) == 3
    assert blocks[0]["type"] == "header"
    assert "core-api" in blocks[0]["text"]["text"]

    fields = blocks[1]["fields"]
    status_text = fields[0]["text"]
    assert "Pass" in status_text
