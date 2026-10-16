"""
Unit tests for DiscordEmbedFormatter.
"""

from agent_engine.tools.discord_embeds import DiscordEmbedFormatter


def test_format_finding_embed():
    result = DiscordEmbedFormatter.format_finding_embed(
        vuln_id="CVE-2024-1234",
        severity="CRITICAL",
        cwe="CWE-79",
        file_path="src/render.js",
        line=15,
        description="Cross-site scripting via unescaped innerHTML insertion.",
        remediation_branch="fix/cve-2024-1234"
    )

    assert "embeds" in result
    assert len(result["embeds"]) == 1
    embed = result["embeds"][0]
    assert embed["color"] == 0xED4245
    assert "CVE-2024-1234" in embed["title"]
    field_names = [f["name"] for f in embed["fields"]]
    assert "Severity" in field_names
    assert "Remediation Branch" in field_names


def test_format_resolved_embed():
    result = DiscordEmbedFormatter.format_resolved_embed(
        vuln_id="CVE-2024-1234",
        pr_number=88,
        pr_url="https://github.com/my-org/app/pull/88",
        verified_tests=24
    )

    assert "embeds" in result
    embed = result["embeds"][0]
    assert embed["color"] == 0x57F287
    assert "#88" in embed["description"]
    assert "24 passing" in embed["fields"][0]["value"]
