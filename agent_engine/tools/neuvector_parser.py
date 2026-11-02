"""Parser for SUSE NeuVector container runtime & image vulnerability scan reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_neuvector_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse NeuVector container scan report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing container image vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    vulns = data.get("vulnerabilities", []) if "vulnerabilities" in data else data.get("report", {}).get("vulnerabilities", [])

    for v in vulns:
        cve_id = v.get("name", "CVE-UNKNOWN")
        desc = v.get("description", "Vulnerability detected in container image by NeuVector.")
        pkg_name = v.get("package_name", "unknown")
        pkg_ver = v.get("package_version", "0.0.0")
        fixed_ver = v.get("fixed_version", "")
        score = float(v.get("score", 5.0))
        sev_raw = str(v.get("severity", "Medium")).upper()

        if sev_raw == "CRITICAL" or score >= 9.0:
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or score >= 7.0:
            severity = SeverityLevel.HIGH
        elif sev_raw == "LOW" or score < 4.0:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        finding = Finding(
            id=f"neuvector-{cve_id.lower()}-{pkg_name}",
            scanner="neuvector",
            finding_type=FindingType.CONTAINER,
            rule_id=cve_id,
            title=f"NeuVector Container Vulnerability: {pkg_name} ({cve_id})",
            description=desc,
            severity=severity,
            cvss_score=score,
            cwe_ids=["CWE-1395"],
            file_path="Dockerfile",
            start_line=1,
            end_line=1,
            vulnerable_code=f"RUN {pkg_name}=={pkg_ver} (Fixed in: {fixed_ver or 'vendor patch'})"
        )
        findings.append(finding)

    return findings
