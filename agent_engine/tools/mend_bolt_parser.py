"""Parser for Mend Bolt (formerly WhiteSource) open-source software security reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_mend_bolt_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Mend Bolt JSON security vulnerability reports into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing SCA dependency vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    # Mend Bolt typically structures findings under 'alerts' or 'vulnerabilities'
    alerts = data.get("alerts", []) if isinstance(data, dict) else []
    if not alerts and isinstance(data, dict):
        alerts = data.get("vulnerabilities", [])

    for idx, alert in enumerate(alerts, start=1):
        vuln = alert.get("vulnerability", alert)
        cve_id = vuln.get("name", vuln.get("cve", f"WS-{idx}"))
        lib_info = alert.get("library", {})
        pkg_name = lib_info.get("name", alert.get("component", "unknown"))
        pkg_version = lib_info.get("version", alert.get("version", "0.0.0"))
        fix_ver = alert.get("fixResolution", alert.get("fixed_in", None))
        sev_raw = str(vuln.get("severity", "MEDIUM")).upper()
        cvss = float(vuln.get("cvss3_score", vuln.get("score", 5.0))) if ("cvss3_score" in vuln or "score" in vuln) else None

        if sev_raw == "CRITICAL" or (cvss and cvss >= 9.0):
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or (cvss and cvss >= 7.0):
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe = vuln.get("cwe", "CWE-1395")
        cwe_list = [cwe] if cwe.startswith("CWE-") else ["CWE-1395"]

        findings.append(
            Finding(
                id=f"mend-bolt-{cve_id}-{pkg_name}",
                scanner="mend-bolt",
                finding_type=FindingType.SCA,
                rule_id=cve_id,
                title=f"{pkg_name} contains vulnerability {cve_id}",
                description=vuln.get("description", f"Mend Bolt detected {cve_id} in {pkg_name} {pkg_version}"),
                severity=severity,
                cwe_ids=cwe_list,
                cvss_score=cvss,
                file_path="requirements.txt",
                start_line=1,
                end_line=1,
                package_name=pkg_name,
                installed_version=pkg_version,
                fixed_version=fix_ver,
                references=vuln.get("references", []),
            )
        )

    return findings
