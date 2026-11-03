"""Formatter for GitLab REST API v4 DevSecOps issue payloads."""

from typing import Any, Dict, List, Optional
from agent_engine.state import Finding, SeverityLevel


class GitlabIssueFormatter:
    """Formats findings into GitLab REST API v4 issue creation payloads."""

    SEVERITY_WEIGHT_MAP = {
        SeverityLevel.CRITICAL: 5,
        SeverityLevel.HIGH: 4,
        SeverityLevel.MEDIUM: 3,
        SeverityLevel.LOW: 2,
        SeverityLevel.INFO: 1,
    }

    @classmethod
    def format_issue_payload(
        cls,
        finding: Finding,
        confidential: bool = True,
        additional_labels: Optional[List[str]] = None,
        patch_summary: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Format a Finding into a GitLab issue creation payload.

        Args:
            finding: Vulnerability Finding object.
            confidential: Whether the issue should be confidential (default True for vulnerabilities).
            additional_labels: Extra labels to attach.
            patch_summary: Remediation status notes.

        Returns:
            Dictionary payload ready for GitLab POST /api/v4/projects/:id/issues.
        """
        weight = cls.SEVERITY_WEIGHT_MAP.get(finding.severity, 3)
        labels = [
            "security",
            f"severity::{finding.severity.value.lower()}",
            f"scanner::{finding.scanner.lower()}",
            "autonomous-remediation",
        ]
        if additional_labels:
            labels.extend(additional_labels)

        title = f"[{finding.severity.value}] Security: {finding.rule_id} in {finding.file_path}"
        if len(title) > 255:
            title = title[:252] + "..."

        description_lines = [
            f"## Vulnerability Advisory: {finding.rule_id}",
            f"**Title:** {finding.title}",
            f"**Severity:** `{finding.severity.value}` | **Weight:** `{weight}`",
            f"**Scanner:** `{finding.scanner}`",
            f"**File:** `{finding.file_path}:{finding.start_line}`",
            f"**CWE:** {', '.join(finding.cwe_ids) if finding.cwe_ids else 'N/A'}",
            "",
            "### Description",
            finding.description,
        ]

        if patch_summary:
            description_lines.extend([
                "",
                "### Autonomous Remediation",
                patch_summary,
            ])

        return {
            "title": title,
            "description": "\n".join(description_lines),
            "confidential": confidential,
            "labels": ",".join(list(set(labels))),
            "weight": weight,
        }
