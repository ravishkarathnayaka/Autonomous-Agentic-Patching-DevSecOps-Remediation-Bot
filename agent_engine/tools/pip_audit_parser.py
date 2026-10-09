"""Parser for pip-audit / Safety Python SCA vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_pip_audit_report(
    report_data: Union[str, Dict[str, Any], Path],
    requirements_path: str = "target_repo/requirements.txt"
) -> List[Finding]:
    """Parse pip-audit JSON report and normalize into Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.
        requirements_path: Target dependency manifest file path.

    Returns:
        List of normalized Finding models with SCA details.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    dependencies = data.get("dependencies", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for dep in dependencies:
        pkg_name = dep.get("name", "")
        pkg_version = dep.get("version", "")
        vulns = dep.get("vulns", [])

        for v in vulns:
            try:
                vuln_id = v.get("id", f"{pkg_name}-vuln")
                aliases = v.get("aliases", [])
                cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
                fix_versions = v.get("fix_versions", [])
                fixed_ver = fix_versions[0] if fix_versions else "latest"
                desc = v.get("description", f"Vulnerability in {pkg_name} {pkg_version}")

                finding = Finding(
                    id=f"pip-audit-{pkg_name}-{cve_id}",
                    scanner="pip-audit",
                    finding_type=FindingType.SCA,
                    rule_id=cve_id,
                    title=f"SCA: Vulnerable dependency {pkg_name}=={pkg_version} ({cve_id})",
                    description=desc,
                    severity=SeverityLevel.HIGH,
                    cwe_ids=["CWE-1395"],  # Dependency on Vulnerable Third-Party Component
                    cvss_score=7.5,
                    file_path=requirements_path,
                    start_line=1,
                    end_line=1,
                    vulnerable_code=f"{pkg_name}=={pkg_version}",
                    package_name=pkg_name,
                    installed_version=pkg_version,
                    fixed_version=fixed_ver,
                    references=aliases
                )
                findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse pip-audit vulnerability: %s", e)
                continue

    logger.info("Parsed %d SCA findings from pip-audit report.", len(findings))
    return findings
