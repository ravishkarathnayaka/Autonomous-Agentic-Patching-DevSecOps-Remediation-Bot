"""Parser for Palo Alto Prisma Cloud Compute container & image vulnerability findings."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_prisma_compute_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Prisma Cloud Compute vulnerability JSON report into normalized Finding models.

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
    # Prisma Compute returns vulnerabilities under 'cveVulnerabilities' or 'vulnerabilities'
    cves = data.get("cveVulnerabilities", []) if "cveVulnerabilities" in data else data.get("vulnerabilities", [])

    for idx, item in enumerate(cves, start=1):
        cve_id = item.get("cve", item.get("id", f"PRISMA-{idx}"))
        pkg_name = item.get("packageName", item.get("package", "unknown"))
        pkg_version = item.get("packageVersion", "0.0.0")
        fix_version = item.get("fixDate", item.get("status", ""))
        sev_raw = str(item.get("severity", "medium")).upper()
        cvss = float(item.get("cvss", 5.0)) if "cvss" in item else None
        cwe = item.get("cwe", "")

        if sev_raw == "CRITICAL" or (cvss and cvss >= 9.0):
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or (cvss and cvss >= 7.0):
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_list = [cwe] if cwe and cwe.startswith("CWE-") else ["CWE-1395"]
        link = item.get("link", f"https://nvd.nist.gov/vuln/detail/{cve_id}")

        findings.append(
            Finding(
                id=f"prisma-compute-{cve_id}-{pkg_name}",
                scanner="prisma-compute",
                finding_type=FindingType.CONTAINER,
                rule_id=cve_id,
                title=f"Container package {pkg_name} vulnerable to {cve_id}",
                description=item.get("description", f"Prisma Compute flagged vulnerability {cve_id} in {pkg_name}."),
                severity=severity,
                cwe_ids=cwe_list,
                cvss_score=cvss,
                file_path=item.get("imageName", "Dockerfile"),
                start_line=1,
                end_line=1,
                package_name=pkg_name,
                installed_version=pkg_version,
                fixed_version=fix_version if fix_version else None,
                references=[link] if link else [],
            )
        )

    return findings
