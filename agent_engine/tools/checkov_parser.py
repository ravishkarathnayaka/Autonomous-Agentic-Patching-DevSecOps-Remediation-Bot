"""Parser for Checkov Infrastructure-as-Code (IaC) and Docker security reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_checkov_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Checkov IaC JSON report and normalize into Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models with IaC misconfigurations.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    # Checkov report can be a dict or a list of test suites
    suites: List[Dict[str, Any]] = [data] if isinstance(data, dict) else data

    findings: List[Finding] = []

    for suite in suites:
        results = suite.get("results", {})
        failed_checks = results.get("failed_checks", [])

        for idx, check in enumerate(failed_checks):
            try:
                check_id = check.get("check_id", f"CKV-{idx}")
                check_name = check.get("check_name", "IaC Security Misconfiguration")
                file_path = check.get("file_path", "").replace("\\", "/").lstrip("./")

                raw_severity = check.get("severity") or "MEDIUM"
                severity_map = {
                    "CRITICAL": SeverityLevel.CRITICAL,
                    "HIGH": SeverityLevel.HIGH,
                    "MEDIUM": SeverityLevel.MEDIUM,
                    "LOW": SeverityLevel.LOW
                }
                severity = severity_map.get(str(raw_severity).upper(), SeverityLevel.MEDIUM)

                line_range = check.get("file_line_range", [1, 1])
                start_line = line_range[0] if line_range else 1
                end_line = line_range[-1] if len(line_range) > 1 else start_line

                guideline = check.get("guideline", "")
                desc = f"{check_name}. {guideline}".strip()

                finding = Finding(
                    id=f"checkov-{check_id}-{file_path}-{start_line}",
                    scanner="checkov",
                    finding_type=FindingType.SAST,
                    rule_id=f"checkov.{check_id}",
                    title=f"IaC Misconfiguration: {check_name}",
                    description=desc,
                    severity=severity,
                    cwe_ids=["CWE-1035"],  # Cryptographic/Configuration Flaw
                    cvss_score=6.0,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    vulnerable_code=f"File: {file_path} (Violates {check_id})"
                )
                findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse Checkov check item: %s", e)
                continue

    logger.info("Parsed %d IaC findings from Checkov report.", len(findings))
    return findings
