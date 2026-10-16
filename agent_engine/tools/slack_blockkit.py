"""
Slack BlockKit Formatter for DevSecOps Alerts
Formats security findings, patch verification results, and remediation PR notifications
into enterprise-ready Slack BlockKit interactive JSON payloads.
"""

from typing import Dict, List, Any, Optional


class SlackBlockKitFormatter:
    """
    Constructs high-fidelity Slack BlockKit message blocks for DevSecOps notifications.
    """

    SEVERITY_EMOJIS = {
        "CRITICAL": ":rotating_light:",
        "HIGH": ":warning:",
        "MEDIUM": ":large_yellow_circle:",
        "LOW": ":information_source:",
        "INFO": ":memo:"
    }

    @classmethod
    def format_finding_alert(
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
        """
        Generate a Slack BlockKit alert for an individual vulnerability finding.
        """
        sev_upper = severity.upper()
        emoji = cls.SEVERITY_EMOJIS.get(sev_upper, ":grey_question:")

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} Security Finding: {vuln_id}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:*\n`{sev_upper}`"},
                    {"type": "mrkdwn", "text": f"*CWE / Rule:*\n`{cwe}`"},
                    {"type": "mrkdwn", "text": f"*File:*\n`{file_path}:{line}`"},
                    {"type": "mrkdwn", "text": f"*Status:*\n*Identified*"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n>{description}"
                }
            }
        ]

        if remediation_branch:
            blocks.append({
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f":git: *Automated remediation branch:* `{remediation_branch}`"}
                ]
            })

        if pr_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View Pull Request", "emoji": True},
                        "url": pr_url,
                        "style": "primary"
                    }
                ]
            })

        return {"blocks": blocks}

    @classmethod
    def format_scan_summary(
        cls,
        repository: str,
        total_scanned: int,
        findings_by_severity: Dict[str, int],
        duration_seconds: float
    ) -> Dict[str, Any]:
        """
        Generate a BlockKit executive summary card for a completed DevSecOps scan run.
        """
        crit = findings_by_severity.get("CRITICAL", 0)
        high = findings_by_severity.get("HIGH", 0)
        med = findings_by_severity.get("MEDIUM", 0)
        low = findings_by_severity.get("LOW", 0)

        status_text = ":white_check_mark: *Pass*" if (crit == 0 and high == 0) else ":x: *Action Required*"

        blocks: List[Dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f":shield: DevSecOps Scan Summary: {repository}",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Overall Status:*\n{status_text}"},
                    {"type": "mrkdwn", "text": f"*Scan Duration:*\n`{duration_seconds:.2f}s`"},
                    {"type": "mrkdwn", "text": f"*Critical / High:*\n`{crit}` / `{high}`"},
                    {"type": "mrkdwn", "text": f"*Medium / Low:*\n`{med}` / `{low}`"}
                ]
            },
            {
                "type": "divider"
            }
        ]

        return {"blocks": blocks}
