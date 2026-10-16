"""
Discord Webhook Embed Formatter for DevSecOps Notifications
Constructs Discord embed objects with color coding, severity badges, and
structured vulnerability metadata for automated security incident dispatch.
"""

from typing import Dict, List, Any, Optional
from datetime import datetime, timezone


class DiscordEmbedFormatter:
    """
    Constructs Discord webhook message payloads with rich embeds.
    """

    COLOR_MAP = {
        "CRITICAL": 0xED4245,  # Discord Red
        "HIGH": 0xE67E22,      # Orange
        "MEDIUM": 0xFEE75C,    # Yellow
        "LOW": 0x3498DB,       # Blue
        "RESOLVED": 0x57F287   # Green
    }

    @classmethod
    def format_finding_embed(
        cls,
        vuln_id: str,
        severity: str,
        cwe: str,
        file_path: str,
        line: int,
        description: str,
        remediation_branch: Optional[str] = None
    ) -> Dict[str, Any]:
        """Format an individual security finding into a Discord embed."""
        sev_upper = severity.upper()
        color = cls.COLOR_MAP.get(sev_upper, 0x95A5A6)

        fields = [
            {"name": "Severity", "value": f"`{sev_upper}`", "inline": True},
            {"name": "CWE / Rule", "value": f"`{cwe}`", "inline": True},
            {"name": "Location", "value": f"`{file_path}:{line}`", "inline": False},
            {"name": "Description", "value": description[:1000], "inline": False}
        ]

        if remediation_branch:
            fields.append({
                "name": "Remediation Branch",
                "value": f"`{remediation_branch}`",
                "inline": False
            })

        embed = {
            "title": f"🚨 DevSecOps Vulnerability Alert: {vuln_id}",
            "color": color,
            "fields": fields,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {
                "text": "Autonomous Agentic Patching Bot • DevSecOps Remediation"
            }
        }

        return {"embeds": [embed]}

    @classmethod
    def format_resolved_embed(
        cls,
        vuln_id: str,
        pr_number: int,
        pr_url: str,
        verified_tests: int
    ) -> Dict[str, Any]:
        """Format a resolution announcement embed when a patch is successfully verified."""
        embed = {
            "title": f"✅ Vulnerability Remediated: {vuln_id}",
            "color": cls.COLOR_MAP["RESOLVED"],
            "description": f"Automated patch verified and submitted in PR [#{pr_number}]({pr_url}).",
            "fields": [
                {"name": "Verified Tests", "value": f"{verified_tests} passing", "inline": True},
                {"name": "Status", "value": "Awaiting Review & Merge", "inline": True}
            ],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "footer": {
                "text": "DevSecOps Autonomous Remediation Bot"
            }
        }
        return {"embeds": [embed]}
