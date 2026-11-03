"""Parser for Check Point Spectral Ops secret scanning reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_spectral_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Spectral Ops JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing leaked secrets or credentials.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    issues = data.get("issues", []) if "issues" in data else data.get("matches", [])

    for idx, issue in enumerate(issues, start=1):
        rule_name = issue.get("rule", {}).get("name", issue.get("rule_name", "spectral-secret"))
        desc = issue.get("rule", {}).get("description", issue.get("description", "Potential secret detected by Spectral."))
        severity_str = str(issue.get("severity", "CRITICAL")).upper()
        file_path = issue.get("location", {}).get("path", issue.get("file", "unknown"))
        line = int(issue.get("location", {}).get("line", issue.get("line_number", 1)))

        if severity_str == "CRITICAL":
            severity = SeverityLevel.CRITICAL
        elif severity_str == "HIGH":
            severity = SeverityLevel.HIGH
        elif severity_str == "LOW":
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        finding = Finding(
            id=f"spectral-{rule_name}-{idx}",
            scanner="spectral",
            finding_type=FindingType.SECRET,
            rule_id=rule_name,
            title=f"Spectral: {rule_name}",
            description=desc,
            severity=severity,
            cwe_ids=["CWE-798"],
            file_path=file_path,
            start_line=line,
            end_line=line,
        )
        findings.append(finding)

    return findings
