"""Parser for Bridgecrew / Checkov Infrastructure-as-Code (IaC) security findings."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_bridgecrew_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Bridgecrew or Checkov JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing IaC misconfigurations.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []

    # Bridgecrew/Checkov output format can have 'results': {'failed_checks': [...]} or top-level list
    results_block = data.get("results", {}) if isinstance(data, dict) else {}
    failed_checks = results_block.get("failed_checks", [])

    if not failed_checks and isinstance(data, dict) and "failed_checks" in data:
        failed_checks = data.get("failed_checks", [])

    for idx, check in enumerate(failed_checks, start=1):
        check_id = check.get("check_id", f"BC-{idx}")
        check_name = check.get("check_name", "IaC Misconfiguration")
        file_path = check.get("file_path", check.get("repo_file_path", "main.tf"))
        # clean file path prefix if present
        if file_path.startswith("/"):
            file_path = file_path.lstrip("/")

        file_line_range = check.get("file_line_range", [1, 1])
        start_line = file_line_range[0] if len(file_line_range) > 0 else 1
        end_line = file_line_range[1] if len(file_line_range) > 1 else start_line

        sev_raw = str(check.get("severity", "MEDIUM")).upper()
        if sev_raw == "CRITICAL":
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH":
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        guideline = check.get("guideline", "")
        code_block = ""
        code_lines = check.get("code_block", [])
        if code_lines and isinstance(code_lines, list):
            code_block = "\n".join([str(line[1]) if isinstance(line, (list, tuple)) and len(line) > 1 else str(line) for line in code_lines])

        findings.append(
            Finding(
                id=f"bridgecrew-{check_id}-{idx}",
                scanner="bridgecrew",
                finding_type=FindingType.IAC,
                rule_id=check_id,
                title=check_name,
                description=guideline or check_name,
                severity=severity,
                cwe_ids=["CWE-16"],  # Configuration CWE
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                vulnerable_code=code_block,
                references=[guideline] if guideline else [],
            )
        )

    return findings
