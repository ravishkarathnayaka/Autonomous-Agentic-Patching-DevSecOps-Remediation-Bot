"""Parser for TFSec Terraform Infrastructure-as-Code JSON security reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

TFSEC_SEV_MAP = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
}


def parse_tfsec_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse TFSec JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to TFSec JSON file.

    Returns:
        List of normalized Finding models for Terraform flaws.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data) if report_data.strip() else {}
    else:
        data = report_data

    results = data.get("results", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for res in results:
        try:
            rule_id = res.get("rule_id", "tfsec-rule")
            rule_desc = res.get("rule_description", "Terraform security misconfiguration")
            raw_sev = str(res.get("severity", "MEDIUM")).upper()
            severity = TFSEC_SEV_MAP.get(raw_sev, SeverityLevel.MEDIUM)
            location = res.get("location", {})
            filename = location.get("filename", "terraform/main.tf")
            start_line = int(location.get("start_line", 1) or 1)
            end_line = int(location.get("end_line", start_line) or start_line)
            resolution = res.get("resolution", "")

            finding = Finding(
                id=f"tfsec-{rule_id.lower()}-{start_line}",
                scanner="tfsec",
                finding_type=FindingType.IAC,
                rule_id=rule_id,
                title=f"TFSec: {rule_desc}",
                description=f"{rule_desc}. Resolution: {resolution}",
                severity=severity,
                cwe_ids=["CWE-16"],
                cvss_score=8.0 if severity == SeverityLevel.HIGH else 5.5,
                file_path=filename,
                start_line=start_line,
                end_line=end_line,
                vulnerable_code=f"# Flagged Terraform block at line {start_line}",
                references=res.get("links", [])
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse TFSec result item: %s", e)
            continue

    logger.info("Successfully parsed %d findings from TFSec report.", len(findings))
    return findings
