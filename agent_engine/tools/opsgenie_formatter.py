"""Atlassian Opsgenie Alert API v2 payload formatter."""

from typing import Any, Dict, List, Optional
from agent_engine.state import Finding, SeverityLevel


class OpsgenieAlertFormatter:
    """Formats vulnerability remediation alerts for Opsgenie incidents."""

    @classmethod
    def format_alert(
        cls,
        finding: Finding,
        status: str = "FAILED_VERIFICATION",
        extra_details: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Convert a Finding and status into an Opsgenie incident payload.

        Args:
            finding: Vulnerability finding model.
            status: Remediation outcome status string.
            extra_details: Additional operational key-values.

        Returns:
            Dict conforming to Opsgenie Create Alert API v2 specification.
        """
        # Map SeverityLevel to Opsgenie Priority (P1-P5)
        if finding.severity == SeverityLevel.CRITICAL:
            priority = "P1"
        elif finding.severity == SeverityLevel.HIGH:
            priority = "P2"
        elif finding.severity == SeverityLevel.MEDIUM:
            priority = "P3"
        elif finding.severity == SeverityLevel.LOW:
            priority = "P4"
        else:
            priority = "P5"

        details = {
            "Scanner": finding.scanner,
            "RuleID": finding.rule_id,
            "CVSS": str(finding.cvss_score),
            "CWE": ", ".join(finding.cwe_ids),
            "FilePath": f"{finding.file_path}:{finding.start_line}",
            "Status": status
        }
        if extra_details:
            details.update(extra_details)

        tags = [
            "devsecops-bot",
            finding.scanner.lower(),
            finding.severity.value.lower()
        ]
        for cwe in finding.cwe_ids:
            tags.append(cwe.lower())

        return {
            "message": f"[{priority}] Remediation {status}: {finding.title}",
            "alias": f"remediation-{finding.id}",
            "description": finding.description,
            "priority": priority,
            "source": "Autonomous-DevSecOps-Remediation-Bot",
            "tags": tags,
            "details": details
        }
