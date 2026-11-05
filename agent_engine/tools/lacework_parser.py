"""Parser for Lacework cloud security posture & container vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_lacework_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Lacework JSON report into normalized Finding models.

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
    vuln_list = data.get("vulnerabilities", []) if "vulnerabilities" in data else data.get("data", [])

    for idx, vuln in enumerate(vuln_list, start=1):
        vuln_id = vuln.get("vuln_id", vuln.get("cve", f"LW-{idx}"))
        pkg_name = vuln.get("feature_name", vuln.get("package", "unknown"))
        pkg_version = vuln.get("version", "0.0.0")
        fix = vuln.get("fix_version", vuln.get("fixed_version", None))
        sev_raw = str(vuln.get("severity", "Medium")).upper()
        cvss_score = float(vuln.get("score", 5.0)) if "score" in vuln else None
        cwe = vuln.get("cwe", "")

        if sev_raw == "CRITICAL" or (cvss_score and cvss_score >= 9.0):
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or (cvss_score and cvss_score >= 7.0):
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_ids: List[str] = []
        if isinstance(cwe, str) and cwe:
            cwe_ids = [cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"]

        finding = Finding(
            id=f"lacework-{vuln_id}-{pkg_name}",
            scanner="lacework",
            finding_type=FindingType.CONTAINER,
            rule_id=vuln_id,
            title=f"Lacework: {vuln_id} in {pkg_name} ({pkg_version})",
            description=f"Vulnerability {vuln_id} detected in container package {pkg_name}.",
            severity=severity,
            cvss_score=cvss_score,
            cwe_ids=cwe_ids,
            file_path="Dockerfile",
            start_line=1,
            end_line=1,
            package_name=pkg_name,
            installed_version=pkg_version,
            fixed_version=fix,
        )
        findings.append(finding)

    return findings
