"""Parser for Aqua Security container & cloud workload vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_aqua_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Aqua Security scan JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing container vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    resources = data.get("resources", []) if "resources" in data else [data]

    for res in resources:
        res_name = res.get("resource", {}).get("name", "container-image")
        vulnerabilities = res.get("vulnerabilities", [])

        for vuln in vulnerabilities:
            vuln_name = vuln.get("name", "AQUA-VULN-UNKNOWN")
            desc = vuln.get("description", "Vulnerability detected by Aqua Security scanner.")
            resource_name = vuln.get("resource", {}).get("name", res_name)
            installed_version = vuln.get("resource", {}).get("version", "0.0.0")
            fix_version = vuln.get("fix_version", "upgrade available")
            nvd_score = float(vuln.get("nvd_score", vuln.get("aqua_score", 5.0)))
            aqua_severity = str(vuln.get("aqua_severity", vuln.get("vendor_severity", "medium"))).upper()

            if aqua_severity == "CRITICAL" or nvd_score >= 9.0:
                severity = SeverityLevel.CRITICAL
            elif aqua_severity == "HIGH" or nvd_score >= 7.0:
                severity = SeverityLevel.HIGH
            elif aqua_severity in ["LOW", "NEGLIGIBLE"] or nvd_score < 4.0:
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.MEDIUM

            cwe_ids = []
            if "cwe" in vuln:
                cwe_ids = [vuln["cwe"]] if isinstance(vuln["cwe"], str) else vuln["cwe"]

            finding = Finding(
                id=f"aqua-{vuln_name}-{resource_name}",
                scanner="aqua",
                finding_type=FindingType.CONTAINER,
                rule_id=vuln_name,
                title=f"Aqua: {vuln_name} in {resource_name} ({installed_version})",
                description=f"{desc} (Remediation: upgrade to {fix_version})",
                severity=severity,
                cwe_ids=cwe_ids,
                file_path="Dockerfile",
                line_start=1,
            )
            findings.append(finding)

    return findings
