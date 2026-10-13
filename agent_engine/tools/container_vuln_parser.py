"""Parser for Container Image OS and Layer vulnerability scan reports (Grype / Docker Scout)."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

CONTAINER_SEV_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "negligible": SeverityLevel.INFO,
    "unknown": SeverityLevel.LOW,
}


def parse_container_vuln_report(
    report_data: Union[str, Dict[str, Any], Path],
    dockerfile_path: str = "docker/sandbox.Dockerfile"
) -> List[Finding]:
    """Parse Grype or container image vulnerability JSON reports into Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.
        dockerfile_path: Target Dockerfile path associated with image.

    Returns:
        List of normalized Finding models with container layer metadata.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    matches = data.get("matches", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for match in matches:
        try:
            vuln = match.get("vulnerability", {})
            pkg = match.get("artifact", {})
            vuln_id = vuln.get("id", "CONTAINER-CVE")
            pkg_name = pkg.get("name", "base-pkg")
            pkg_ver = pkg.get("version", "0.0.0")
            raw_sev = str(vuln.get("severity", "medium")).lower()
            severity = CONTAINER_SEV_MAP.get(raw_sev, SeverityLevel.MEDIUM)
            desc = vuln.get("description", f"Container OS package vulnerability in {pkg_name} {pkg_ver}")

            fix = vuln.get("fix", {})
            fixed_versions = fix.get("versions", [])
            fixed_ver = fixed_versions[0] if fixed_versions else "upgrade package"

            cvss = vuln.get("cvss", [])
            cvss_score = float(cvss[0].get("metrics", {}).get("baseScore", 7.0)) if cvss else None

            finding = Finding(
                id=f"container-{pkg_name}-{vuln_id}",
                scanner="grype",
                finding_type=FindingType.SCA,
                rule_id=vuln_id,
                title=f"Container Vulnerability: {pkg_name} ({vuln_id})",
                description=desc,
                severity=severity,
                cwe_ids=["CWE-1395"],
                cvss_score=cvss_score,
                file_path=dockerfile_path,
                start_line=1,
                end_line=1,
                vulnerable_code=f"RUN apt-get install {pkg_name}={pkg_ver}",
                package_name=pkg_name,
                installed_version=pkg_ver,
                fixed_version=fixed_ver,
                references=vuln.get("urls", [])
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse container vulnerability match: %s", e)
            continue

    logger.info("Successfully parsed %d container findings.", len(findings))
    return findings
