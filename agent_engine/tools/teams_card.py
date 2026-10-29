"""Microsoft Teams Adaptive Card formatter for DevSecOps incident notifications."""

from typing import Any, Dict, Optional


class TeamsAdaptiveCardFormatter:
    """Constructs Microsoft Teams Adaptive Card 1.4 payloads for webhook dispatches."""

    SEVERITY_COLORS = {
        "CRITICAL": "Attention",
        "HIGH": "Warning",
        "MEDIUM": "Accent",
        "LOW": "Default",
    }

    @classmethod
    def format_finding_card(
        cls,
        vuln_id: str,
        severity: str,
        cwe: str,
        file_path: str,
        line: int,
        description: str,
        remediation_branch: Optional[str] = None,
        pr_url: Optional[str] = None
    ) -> Dict[str, Any]:
        """Construct an Adaptive Card payload for a security finding."""
        sev_upper = severity.upper()
        color = cls.SEVERITY_COLORS.get(sev_upper, "Default")

        body: list = [
            {
                "type": "TextBlock",
                "size": "Medium",
                "weight": "Bolder",
                "color": color,
                "text": f"🛡️ DevSecOps Security Finding: {vuln_id}"
            },
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Severity:", "value": sev_upper},
                    {"title": "CWE / Rule:", "value": cwe},
                    {"title": "Location:", "value": f"{file_path}:{line}"},
                    {"title": "Remediation Branch:", "value": remediation_branch or "N/A"}
                ]
            },
            {
                "type": "TextBlock",
                "text": description,
                "wrap": True
            }
        ]

        actions = []
        if pr_url:
            actions.append({
                "type": "Action.OpenUrl",
                "title": "View Remediated Pull Request",
                "url": pr_url
            })

        card = {
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": body,
            "actions": actions
        }

        # Format as Teams Connector envelope
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": card
                }
            ]
        }
