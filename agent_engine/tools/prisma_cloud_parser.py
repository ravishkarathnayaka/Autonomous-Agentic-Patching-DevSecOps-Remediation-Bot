"""Parser for Palo Alto Networks Prisma Cloud Compute (Twistlock) container scans."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_prisma_cloud_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Prisma Cloud container vulnerability report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    vulns = data.get("vulnerabilities", [])

    for v in vulns:
        cve_id = v.get("cve", v.get("id", "CVE-UNKNOWN"))
        desc = v.get("description", "Container vulnerability reported by Prisma Cloud Compute.")
        pkg_name = v.get("packageName", "unknown-package")
        pkg_ver = v.get("packageVersion", "0.0.0")
        score = float(v.get("cvss", 5.0))
        sev_raw = str(v.get("severity", "medium")).upper()

        if sev_raw == "CRITICAL" or score >= 9.0:
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or score >= 7.0:
            severity = SeverityLevel.HIGH
        elif sev_raw == "LOW" or score < 4.0:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        finding = Finding(
            id=f"prisma-{cve_id.lower()}-{pkg_name}",
            scanner="prisma-cloud",
            finding_type=FindingType.CONTAINER,
            rule_id=cve_id,
            title=f"Prisma Cloud Vulnerability: {pkg_name} ({cve_id})",
            description=desc,
            severity=severity,
            cvss_score=score,
            cwe_ids=["CWE-1395"],
            file_path="Dockerfile",
            start_line=1,
            end_line=1,
            vulnerable_code=f"RUN base_pkg: {pkg_name}=={pkg_ver}"
        )
        findings.append(finding)

    return findings
