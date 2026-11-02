"""Parser for Snyk Container CLI image vulnerability scan JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_snyk_container_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Snyk Container scan JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing container base image flaws.
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
        snyk_id = v.get("id", "SNYK-CONTAINER-001")
        cves = v.get("identifiers", {}).get("CVE", [])
        cve_id = cves[0] if cves else snyk_id
        title = v.get("title", f"Snyk Container Vulnerability: {snyk_id}")
        desc = v.get("description", title)
        pkg_name = v.get("packageName", "unknown-package")
        pkg_ver = v.get("version", "0.0.0")
        fixed_ver = v.get("nearestFixedInVersion", "")
        score = float(v.get("cvssScore", 5.0))
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
            id=f"snyk-container-{snyk_id.lower()}",
            scanner="snyk-container",
            finding_type=FindingType.CONTAINER,
            rule_id=cve_id,
            title=f"Snyk Container: {pkg_name} ({cve_id})",
            description=desc,
            severity=severity,
            cvss_score=score,
            cwe_ids=["CWE-1395"],
            file_path="Dockerfile",
            start_line=1,
            end_line=1,
            vulnerable_code=f"BASE IMAGE PKG: {pkg_name}=={pkg_ver} (Upgrade to {fixed_ver or 'patched tag'})"
        )
        findings.append(finding)

    return findings
