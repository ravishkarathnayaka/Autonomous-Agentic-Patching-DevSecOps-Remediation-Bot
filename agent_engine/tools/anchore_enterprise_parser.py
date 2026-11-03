"""Parser for Anchore Enterprise container image vulnerability assessment reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_anchore_enterprise_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Anchore Enterprise JSON report into normalized Finding models.

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
    vuln_list = data.get("vulnerabilities", []) if "vulnerabilities" in data else data.get("findings", [])

    for vuln in vuln_list:
        vuln_id = vuln.get("vuln", vuln.get("vulnerability_id", "CVE-UNKNOWN"))
        pkg_name = vuln.get("package_name", vuln.get("package", "unknown"))
        pkg_version = vuln.get("package_version", "0.0.0")
        fix = vuln.get("fix", vuln.get("fix_version", "None"))
        url = vuln.get("url", "")
        sev_raw = str(vuln.get("severity", "Medium")).upper()

        if sev_raw == "CRITICAL":
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH":
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "NEGLIGIBLE"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        nvd_data = vuln.get("nvd_data", [{}])
        cvss_score = None
        if nvd_data and isinstance(nvd_data, list) and "cvss_v3" in nvd_data[0]:
            cvss_score = float(nvd_data[0]["cvss_v3"].get("base_score", 5.0))

        finding = Finding(
            id=f"anchore-{vuln_id}-{pkg_name}",
            scanner="anchore",
            finding_type=FindingType.CONTAINER,
            rule_id=vuln_id,
            title=f"Anchore: {vuln_id} in {pkg_name} ({pkg_version})",
            description=f"Vulnerability {vuln_id} detected in {pkg_name}. Fix available: {fix}",
            severity=severity,
            cvss_score=cvss_score,
            cwe_ids=[],
            file_path="Dockerfile",
            start_line=1,
            end_line=1,
            package_name=pkg_name,
            installed_version=pkg_version,
            fixed_version=fix if fix != "None" else None,
            references=[url] if url else [],
        )
        findings.append(finding)

    return findings
