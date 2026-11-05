"""Parser for SonarCloud API static analysis issue telemetry reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_sonarcloud_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse SonarCloud issues JSON export into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing static code vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    issues = data.get("issues", [])

    for idx, issue in enumerate(issues, start=1):
        key = issue.get("key", f"SC-{idx}")
        rule = issue.get("rule", "sonar:S0000")
        message = issue.get("message", "SonarCloud code security finding.")
        component = issue.get("component", "app.py")
        file_path = component.split(":")[-1] if ":" in component else component
        line = int(issue.get("line", issue.get("textRange", {}).get("startLine", 1)))
        sev_raw = str(issue.get("severity", "MAJOR")).upper()

        if sev_raw == "BLOCKER":
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "CRITICAL":
            severity = SeverityLevel.HIGH
        elif sev_raw in ["MINOR", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        finding = Finding(
            id=f"sonarcloud-{key}",
            scanner="sonarcloud",
            finding_type=FindingType.SAST,
            rule_id=rule,
            title=f"SonarCloud: {message[:120]}",
            description=message,
            severity=severity,
            cwe_ids=[],
            file_path=file_path,
            start_line=line,
            end_line=line,
        )
        findings.append(finding)

    return findings
