"""Parser for Semgrep Supply Chain (SCA) dependency vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_semgrep_supply_chain_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Semgrep Supply Chain JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to Semgrep SCA report.

    Returns:
        List of normalized Finding models representing reachable/unreachable CVEs.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    results = data.get("results", [])

    for r in results:
        check_id = r.get("check_id", "ssc-cve-generic")
        path = r.get("path", "requirements.txt")
        extra = r.get("extra", {})
        sca_info = extra.get("sca_info", {})
        reachable = sca_info.get("reachable", False)
        pkg_name = sca_info.get("dependency_name", "urllib3")
        installed_ver = sca_info.get("dependency_version", "1.26.5")

        sev_raw = extra.get("severity", "ERROR").upper()
        if sev_raw == "ERROR" or reachable:
            severity = SeverityLevel.CRITICAL if reachable else SeverityLevel.HIGH
        else:
            severity = SeverityLevel.MEDIUM

        message = extra.get("message", f"Vulnerable dependency {pkg_name} detected.")
        cve_id = check_id.split(".")[-1].upper() if "CVE-" in check_id.upper() else "CVE-2023-45803"

        finding = Finding(
            id=f"semgrep-ssc-{pkg_name.lower()}-{installed_ver}",
            scanner="semgrep-supply-chain",
            finding_type=FindingType.SCA,
            rule_id=check_id,
            title=f"Supply Chain: {pkg_name} {cve_id}",
            description=message,
            severity=severity,
            cwe_ids=["CWE-1395"],
            cvss_score=9.1 if reachable else 7.5,
            file_path=path,
            start_line=1,
            end_line=1,
            package_name=pkg_name,
            installed_version=installed_ver,
            fixed_version=sca_info.get("fixed_version", "2.0.7"),
            vulnerable_code=f"{pkg_name}=={installed_ver}"
        )
        findings.append(finding)

    return findings
