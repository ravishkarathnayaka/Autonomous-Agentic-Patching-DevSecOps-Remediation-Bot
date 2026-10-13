"""Parser for Brakeman Ruby on Rails SAST JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

BRAKEMAN_CONFIDENCE_MAP = {
    "High": SeverityLevel.HIGH,
    "Medium": SeverityLevel.MEDIUM,
    "Weak": SeverityLevel.LOW,
}


def parse_brakeman_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Brakeman SAST JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to Brakeman report JSON.

    Returns:
        List of normalized Finding models.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    warnings = data.get("warnings", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for warn in warnings:
        try:
            warning_type = warn.get("warning_type", "Security Warning")
            check_name = warn.get("check_name", "BrakemanCheck")
            message = warn.get("message", warning_type)
            file_path = warn.get("file", "app/controllers/application_controller.rb")
            line = warn.get("line", 1) or 1
            code = warn.get("code", "")
            confidence = warn.get("confidence", "Medium")
            severity = BRAKEMAN_CONFIDENCE_MAP.get(confidence, SeverityLevel.MEDIUM)
            cwe_id = warn.get("cwe_id")
            cwe_list = [f"CWE-{cwe_id[0]}"] if isinstance(cwe_id, list) and cwe_id else ["CWE-20"]

            finding = Finding(
                id=f"brakeman-{check_name}-{line}",
                scanner="brakeman",
                finding_type=FindingType.SAST,
                rule_id=check_name,
                title=f"Brakeman: {warning_type} ({check_name})",
                description=message,
                severity=severity,
                cwe_ids=cwe_list,
                cvss_score=7.5 if severity == SeverityLevel.HIGH else 5.0,
                file_path=file_path,
                start_line=line,
                end_line=line,
                vulnerable_code=code or f"# Line {line}: {message}",
                references=[warn.get("link")] if warn.get("link") else []
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse Brakeman warning: %s", e)
            continue

    logger.info("Successfully parsed %d findings from Brakeman report.", len(findings))
    return findings
