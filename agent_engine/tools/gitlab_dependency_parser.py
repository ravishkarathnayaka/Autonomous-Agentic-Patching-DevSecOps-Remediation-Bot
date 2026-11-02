"""Parser for GitLab Dependency Scanning JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_gitlab_dependency_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse GitLab Dependency Scanning JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing dependency CVEs.
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
        cve = v.get("cve", v.get("id", "CVE-UNKNOWN"))
        name = v.get("name", cve)
        desc = v.get("description", v.get("message", "GitLab Dependency Scanning vulnerability."))
        sev_raw = str(v.get("severity", "Medium")).upper()

        if sev_raw == "CRITICAL":
            severity = SeverityLevel.CRITICAL
            cvss = 9.5
        elif sev_raw == "HIGH":
            severity = SeverityLevel.HIGH
            cvss = 7.5
        elif sev_raw == "LOW":
            severity = SeverityLevel.LOW
            cvss = 3.5
        else:
            severity = SeverityLevel.MEDIUM
            cvss = 5.0

        loc = v.get("location", {})
        file_path = loc.get("file", "requirements.txt")
        pkg_name = loc.get("dependency", {}).get("package", {}).get("name", "unknown-package")
        pkg_ver = loc.get("dependency", {}).get("version", "0.0.0")

        finding = Finding(
            id=f"gitlab-dep-{cve.lower()}-{pkg_name}",
            scanner="gitlab-dependency-scanning",
            finding_type=FindingType.SCA,
            rule_id=cve,
            title=f"GitLab Dependency Alert: {pkg_name} ({cve})",
            description=desc,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=["CWE-1395"],
            file_path=file_path,
            start_line=1,
            end_line=1,
            vulnerable_code=f"{pkg_name}=={pkg_ver}"
        )
        findings.append(finding)

    return findings
