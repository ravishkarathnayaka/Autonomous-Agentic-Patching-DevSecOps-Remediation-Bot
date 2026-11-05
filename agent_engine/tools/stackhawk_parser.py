"""Parser for StackHawk DAST scan reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_stackhawk_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse StackHawk JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing dynamic API findings.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    issues = data.get("findings", []) if "findings" in data else data.get("alerts", [])

    for idx, issue in enumerate(issues, start=1):
        plugin_id = str(issue.get("pluginId", issue.get("id", f"HAWK-{idx}")))
        name = issue.get("name", issue.get("title", "StackHawk Finding"))
        desc = issue.get("description", "Vulnerability detected by StackHawk DAST.")
        severity_str = str(issue.get("severity", "Medium")).upper()
        cwe = issue.get("cweId", issue.get("cwe", ""))
        url_path = issue.get("path", issue.get("uri", "/api/v1"))

        if severity_str == "CRITICAL":
            severity = SeverityLevel.CRITICAL
        elif severity_str == "HIGH":
            severity = SeverityLevel.HIGH
        elif severity_str == "LOW":
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_ids = []
        if cwe:
            cwe_str = str(cwe)
            cwe_ids.append(cwe_str if cwe_str.startswith("CWE-") else f"CWE-{cwe_str}")

        finding = Finding(
            id=f"stackhawk-{plugin_id}-{idx}",
            scanner="stackhawk",
            finding_type=FindingType.DAST,
            rule_id=f"HAWK-{plugin_id}",
            title=f"StackHawk: {name} at {url_path}",
            description=desc,
            severity=severity,
            cwe_ids=cwe_ids,
            file_path="target_repo/app.py",
            start_line=1,
            end_line=1,
        )
        findings.append(finding)

    return findings
