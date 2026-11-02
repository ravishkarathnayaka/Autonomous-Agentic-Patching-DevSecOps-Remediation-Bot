"""Formatter for Atlassian Jira DevSecOps issue payloads."""

from typing import Any, Dict, List, Optional
from agent_engine.state import Finding, SeverityLevel


class JiraTicketFormatter:
    """Formats findings into Atlassian Jira REST API v3 issue creation payloads."""

    SEVERITY_TO_PRIORITY = {
        SeverityLevel.CRITICAL: "Highest",
        SeverityLevel.HIGH: "High",
        SeverityLevel.MEDIUM: "Medium",
        SeverityLevel.LOW: "Low",
        SeverityLevel.INFO: "Lowest",
    }

    @classmethod
    def format_issue_payload(
        cls,
        finding: Finding,
        project_key: str = "SEC",
        issue_type: str = "Vulnerability",
        additional_labels: Optional[List[str]] = None,
        patch_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Format a Finding into a Jira issue creation dict.

        Args:
            finding: Vulnerability Finding object.
            project_key: Jira project key.
            issue_type: Issue type name.
            additional_labels: Extra labels to attach.
            patch_summary: Brief note explaining remediation status.

        Returns:
            Dictionary payload ready for Jira REST API POST /rest/api/3/issue.
        """
        priority = cls.SEVERITY_TO_PRIORITY.get(finding.severity, "Medium")
        labels = ["autonomous-sec-bot", finding.scanner.lower(), finding.finding_type.value.lower()]
        if additional_labels:
            labels.extend(additional_labels)

        summary = f"[{finding.severity.value}] {finding.rule_id}: {finding.title}"
        if len(summary) > 250:
            summary = summary[:247] + "..."

        description_lines = [
            f"*Scanner:* {finding.scanner}",
            f"*Rule ID:* {finding.rule_id}",
            f"*Severity:* {finding.severity.value}",
            f"*File:* {finding.file_path}",
            f"*CWE:* {', '.join(finding.cwe_ids) if finding.cwe_ids else 'N/A'}",
            "",
            "h3. Vulnerability Description",
            finding.description,
        ]

        if patch_summary:
            description_lines.extend([
                "",
                "h3. Autonomous Remediation Status",
                patch_summary,
            ])

        return {
            "fields": {
                "project": {"key": project_key},
                "issuetype": {"name": issue_type},
                "summary": summary,
                "priority": {"name": priority},
                "labels": list(set(labels)),
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "\n".join(description_lines),
                                }
                            ],
                        }
                    ],
                },
            }
        }
