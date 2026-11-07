"""Parser for Prowler AWS, Azure, and GCP cloud security compliance findings."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_prowler_report(report_data: Union[str, Dict[str, Any], Path, List[Dict[str, Any]]]) -> List[Finding]:
    """Parse Prowler JSON security assessment report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict/list, or Path to JSON file.

    Returns:
        List of normalized Finding models representing cloud security misconfigurations.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []

    # Prowler outputs a list of check objects or a dict with 'results' / 'findings'
    items = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("findings", data.get("results", []))

    for idx, item in enumerate(items, start=1):
        status = str(item.get("Status", item.get("status", "FAIL"))).upper()
        # Only process failed security checks
        if status not in ["FAIL", "FAILED"]:
            continue

        check_id = item.get("CheckID", item.get("check_id", f"PROWLER-{idx}"))
        title = item.get("CheckTitle", item.get("title", "Prowler Cloud Security Check"))
        service = item.get("ServiceName", item.get("service", "cloud"))
        resource_id = item.get("ResourceId", item.get("resource_id", "arn:aws:..."))
        sev_raw = str(item.get("Severity", item.get("severity", "medium"))).upper()

        if sev_raw == "CRITICAL":
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH":
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFORMATIONAL", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        risk = item.get("Risk", item.get("description", title))
        remediation = item.get("Remediation", {})
        remediation_code = remediation.get("Code", {}) if isinstance(remediation, dict) else {}
        cli_example = remediation_code.get("CLI", "") if isinstance(remediation_code, dict) else ""

        findings.append(
            Finding(
                id=f"prowler-{check_id}-{idx}",
                scanner="prowler",
                finding_type=FindingType.CLOUD,
                rule_id=check_id,
                title=f"[{service.upper()}] {title}",
                description=risk,
                severity=severity,
                cwe_ids=["CWE-16"],
                file_path=str(resource_id),
                start_line=1,
                end_line=1,
                vulnerable_code=cli_example,
                references=[remediation.get("Url", "")] if isinstance(remediation, dict) and remediation.get("Url") else [],
            )
        )

    return findings
