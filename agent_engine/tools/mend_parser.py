"""Parser for Mend (formerly WhiteSource) open source SCA vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_mend_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Mend SCA report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing third-party library CVEs.
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
        cve_id = v.get("name", "CVE-UNKNOWN")
        desc = v.get("description", "Open source dependency vulnerability identified by Mend.")
        lib_info = v.get("library", {})
        pkg_name = lib_info.get("artifactId", lib_info.get("name", "unknown-package"))
        pkg_ver = lib_info.get("version", "0.0.0")
        
        cvss_score = float(v.get("cvss3_score", v.get("score", 5.0)))
        severity_raw = str(v.get("severity", "medium")).upper()

        if severity_raw == "CRITICAL" or cvss_score >= 9.0:
            severity = SeverityLevel.CRITICAL
        elif severity_raw == "HIGH" or cvss_score >= 7.0:
            severity = SeverityLevel.HIGH
        elif severity_raw == "LOW" or cvss_score < 4.0:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        top_fix = v.get("topFix", {}).get("fixResolution", "")

        finding = Finding(
            id=f"mend-{cve_id.lower()}",
            scanner="mend",
            finding_type=FindingType.SCA,
            rule_id=cve_id,
            title=f"Mend Dependency Vulnerability: {pkg_name} ({cve_id})",
            description=desc,
            severity=severity,
            cvss_score=cvss_score,
            cwe_ids=["CWE-1395"],
            file_path="requirements.txt",
            start_line=1,
            end_line=1,
            vulnerable_code=f"{pkg_name}=={pkg_ver} (Recommended fix: {top_fix})"
        )
        findings.append(finding)

    return findings
