from agent_engine.tools.teams_card import TeamsAdaptiveCardFormatter


def test_format_teams_card():
    payload = TeamsAdaptiveCardFormatter.format_finding_card(
        vuln_id="CVE-2024-5555",
        severity="CRITICAL",
        cwe="CWE-89",
        file_path="app.py",
        line=28,
        description="SQL injection in search endpoint",
        remediation_branch="security/fix-cwe-89",
        pr_url="https://github.com/org/repo/pull/42"
    )

    assert payload["type"] == "message"
    card = payload["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard"
    assert card["version"] == "1.4"
    assert len(card["actions"]) == 1
    assert card["actions"][0]["url"] == "https://github.com/org/repo/pull/42"
