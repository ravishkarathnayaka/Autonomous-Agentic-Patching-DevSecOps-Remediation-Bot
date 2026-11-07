"""Formatter for OWASP DefectDojo vulnerability management REST API v2 payloads."""

from typing import Any, Dict, List, Optional
from agent_engine.state import Finding, SeverityLevel


class DefectDojoFormatter:
    """Formats normalized Finding objects into OWASP DefectDojo v2 findings payloads."""

    SEVERITY_MAP = {
        SeverityLevel.CRITICAL: "Critical",
        SeverityLevel.HIGH: "High",
        SeverityLevel.MEDIUM: "Medium",
        SeverityLevel.LOW: "Low",
        SeverityLevel.INFO: "Info",
    }

    @classmethod
    def format_finding(
        cls,
        finding: Finding,
        test_id: int = 1,
        is_verified: bool = True,
        mitigation_summary: Optional[str] = None,
        additional_tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Format a Finding into DefectDojo /api/v2/findings/ payload dict.

        Args:
            finding: Normalized Finding object.
            test_id: DefectDojo Test engagement ID.
            is_verified: Whether verification tests passed.
            mitigation_summary: Note explaining remediation status.
            additional_tags: Extra tag strings.

        Returns:
            Dictionary matching DefectDojo API v2 finding schema.
        """
        sev = cls.SEVERITY_MAP.get(finding.severity, "Medium")
        cwe_int = None
        if finding.cwe_ids:
            for cwe in finding.cwe_ids:
                if cwe.startswith("CWE-") and cwe[4:].isdigit():
                    cwe_int = int(cwe[4:])
                    break

        tags = ["autonomous-sec-bot", finding.scanner.lower(), finding.finding_type.value.lower()]
        if additional_tags:
            tags.extend(additional_tags)

        desc_lines = [
            f"**Scanner:** {finding.scanner}",
            f"**Type:** {finding.finding_type.value}",
            f"**Vulnerability ID:** {finding.rule_id}",
            f"**File:** `{finding.file_path}:{finding.start_line}`",
            "",
            "### Description",
            finding.description or "No extended description provided.",
        ]

        if finding.vulnerable_code:
            desc_lines.extend(["", "### Vulnerable Code", f"```\n{finding.vulnerable_code}\n```"])

        return {
            "test": test_id,
            "title": f"[{finding.severity.value}] {finding.rule_id}: {finding.title}",
            "description": "\n".join(desc_lines),
            "severity": sev,
            "cwe": cwe_int,
            "cve": finding.rule_id if finding.rule_id.startswith("CVE-") else None,
            "cvssv3_score": str(finding.cvss_score) if finding.cvss_score is not None else None,
            "file_path": finding.file_path,
            "line": finding.start_line,
            "active": True,
            "verified": is_verified,
            "mitigation": mitigation_summary or "Autonomous patch generated and verified via sandbox test runner.",
            "tags": tags,
        }
