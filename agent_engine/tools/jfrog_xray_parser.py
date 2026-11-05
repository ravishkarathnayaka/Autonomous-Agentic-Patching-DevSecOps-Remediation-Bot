"""Parser for JFrog Xray component & artifact vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_jfrog_xray_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse JFrog Xray JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing SCA/artifact vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    issues = data.get("data", []) if "data" in data else data.get("issues", [])

    for idx, issue in enumerate(issues, start=1):
        issue_id = issue.get("issue_id", f"XRAY-{idx}")
        summary = issue.get("summary", "Vulnerability detected by JFrog Xray.")
        desc = issue.get("description", summary)
        sev_raw = str(issue.get("severity", "Medium")).upper()
        cves = issue.get("cves", [])
        cve_id = cves[0].get("cve", issue_id) if cves and isinstance(cves, list) else issue_id
        cvss_score = float(cves[0].get("cvss_v3_score", 5.0)) if cves and isinstance(cves, list) and "cvss_v3_score" in cves[0] else None

        components = issue.get("components", {})
        pkg_name = "unknown"
        pkg_ver = "0.0.0"
        fixed_ver = None
        if components and isinstance(components, dict):
            comp_key = next(iter(components.keys()))
            pkg_name = comp_key.split("://")[-1].split(":")[0] if "://" in comp_key else comp_key
            fixed_versions = components[comp_key].get("fixed_versions", [])
            fixed_ver = fixed_versions[0] if fixed_versions else None

        if sev_raw == "CRITICAL" or (cvss_score and cvss_score >= 9.0):
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or (cvss_score and cvss_score >= 7.0):
            severity = SeverityLevel.HIGH
        elif sev_raw == "LOW" or (cvss_score and cvss_score < 4.0):
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        finding = Finding(
            id=f"xray-{issue_id}-{idx}",
            scanner="jfrog-xray",
            finding_type=FindingType.SCA,
            rule_id=cve_id,
            title=f"JFrog Xray: {cve_id} in {pkg_name}",
            description=desc,
            severity=severity,
            cvss_score=cvss_score,
            cwe_ids=[],
            file_path="requirements.txt",
            start_line=1,
            end_line=1,
            package_name=pkg_name,
            installed_version=pkg_ver,
            fixed_version=fixed_ver,
        )
        findings.append(finding)

    return findings
