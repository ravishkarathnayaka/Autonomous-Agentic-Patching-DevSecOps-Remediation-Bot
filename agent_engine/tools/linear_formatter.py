"""Formatter for Linear DevSecOps issue payloads."""

from typing import Any, Dict, List, Optional
from agent_engine.state import Finding, SeverityLevel


class LinearTicketFormatter:
    """Formats findings into Linear API issue creation payloads."""

    # Linear priorities: 0 = No priority, 1 = Urgent, 2 = High, 3 = Medium, 4 = Low
    SEVERITY_TO_PRIORITY = {
        SeverityLevel.CRITICAL: 1,  # Urgent
        SeverityLevel.HIGH: 2,      # High
        SeverityLevel.MEDIUM: 3,    # Medium
        SeverityLevel.LOW: 4,       # Low
        SeverityLevel.INFO: 0,      # None
    }

    @classmethod
    def format_issue_payload(
        cls,
        finding: Finding,
        team_id: str = "team_sec_01",
        additional_labels: Optional[List[str]] = None,
        patch_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Format a Finding into a Linear issue creation dictionary.

        Args:
            finding: Vulnerability Finding object.
            team_id: Linear Team ID.
            additional_labels: Extra label names to attach.
            patch_summary: Brief note explaining automated remediation status.

        Returns:
            Dictionary payload ready for Linear GraphQL createIssue mutation.
        """
        priority = cls.SEVERITY_TO_PRIORITY.get(finding.severity, 3)
        labels = ["security", "bot-remediated", finding.scanner.lower(), finding.finding_type.value.lower()]
        if additional_labels:
            labels.extend(additional_labels)

        title = f"[{finding.severity.value}] {finding.rule_id}: {finding.title}"
        if len(title) > 250:
            title = title[:247] + "..."

        description_lines = [
            f"### Security Finding Details",
            f"- **Scanner:** `{finding.scanner}`",
            f"- **Finding Type:** `{finding.finding_type.value}`",
            f"- **Rule / Vulnerability ID:** `{finding.rule_id}`",
            f"- **Severity:** **{finding.severity.value}**",
            f"- **Location:** `{finding.file_path}:{finding.start_line}`",
        ]

        if finding.cwe_ids:
            description_lines.append(f"- **CWEs:** {', '.join(finding.cwe_ids)}")
        if finding.cvss_score:
            description_lines.append(f"- **CVSS Score:** `{finding.cvss_score}`")

        description_lines.append("\n#### Vulnerability Description")
        description_lines.append(finding.description or "No extended description provided.")

        if finding.vulnerable_code:
            description_lines.append("\n#### Vulnerable Code Snippet")
            description_lines.append(f"```\n{finding.vulnerable_code}\n```")

        if patch_summary:
            description_lines.append("\n#### Automated Remediation Status")
            description_lines.append(f"> {patch_summary}")

        if finding.references:
            description_lines.append("\n#### Advisory References")
            for ref in finding.references[:5]:
                description_lines.append(f"- {ref}")

        return {
            "teamId": team_id,
            "title": title,
            "description": "\n".join(description_lines),
            "priority": priority,
            "labels": labels,
        }
