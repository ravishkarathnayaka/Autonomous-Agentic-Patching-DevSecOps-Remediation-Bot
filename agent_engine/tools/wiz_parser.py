"""Parser for Wiz cloud security posture & vulnerability management reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_wiz_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Wiz JSON findings into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing cloud & OS vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    items = data.get("findings", []) if isinstance(data, dict) else []
    if not items and isinstance(data, dict):
        items = data.get("vulnerabilities", [])

    for idx, item in enumerate(items, start=1):
        vuln_id = item.get("id", item.get("cve", f"WIZ-{idx}"))
        name = item.get("name", item.get("title", "Cloud Security Finding"))
        description = item.get("description", name)
        sev_raw = str(item.get("severity", "MEDIUM")).upper()
        score = float(item.get("score", item.get("cvss", 5.0))) if ("score" in item or "cvss" in item) else None
        cwe = item.get("cwe", "")
        asset = item.get("asset", item.get("resourceName", "cloud_resource"))

        if sev_raw == "CRITICAL" or (score and score >= 9.0):
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or (score and score >= 7.0):
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFORMATIONAL", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_list = [cwe] if cwe and cwe.startswith("CWE-") else ["CWE-16"]

        findings.append(
            Finding(
                id=f"wiz-{vuln_id}-{idx}",
                scanner="wiz",
                finding_type=FindingType.CLOUD,
                rule_id=vuln_id,
                title=f"{name} on {asset}",
                description=description,
                severity=severity,
                cwe_ids=cwe_list,
                cvss_score=score,
                file_path=str(asset),
                start_line=1,
                end_line=1,
                references=item.get("links", []),
            )
        )

    return findings
