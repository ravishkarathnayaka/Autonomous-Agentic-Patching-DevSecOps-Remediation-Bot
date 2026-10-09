"""Parser for Snyk SCA and Container vulnerability JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": SeverityLevel.CRITICAL,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
}


def parse_snyk_report(
    report_data: Union[str, Dict[str, Any], Path],
    manifest_path: str = "target_repo/requirements.txt"
) -> List[Finding]:
    """Parse Snyk JSON CLI report (snyk test --json) into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.
        manifest_path: Path to the target dependency manifest or lockfile.

    Returns:
        List of normalized Finding models with SCA package metadata.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    # Snyk output can be a single dict or a list of test targets
    test_runs = data if isinstance(data, list) else [data]
    findings: List[Finding] = []

    for run in test_runs:
        vulnerabilities = run.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            try:
                vuln_id = vuln.get("id", "snyk-vuln")
                pkg_name = vuln.get("packageName", vuln.get("package", "unknown-package"))
                pkg_version = vuln.get("version", "unknown")
                raw_sev = str(vuln.get("severity", "medium")).lower()
                severity = SEVERITY_MAP.get(raw_sev, SeverityLevel.MEDIUM)
                title = vuln.get("title", f"Vulnerability in {pkg_name}")
                desc = vuln.get("description", title)
                cvss_score = vuln.get("cvssScore", 7.0)

                # Extract CVE and CWE identifiers
                identifiers = vuln.get("identifiers", {})
                cve_list = identifiers.get("CVE", [])
                cwe_list = identifiers.get("CWE", [])
                rule_id = cve_list[0] if cve_list else vuln_id

                # Fixed version
                upgrade_path = vuln.get("upgradePath", [])
                fixed_ver = None
                if upgrade_path and len(upgrade_path) > 1 and isinstance(upgrade_path[1], str):
                    # Often formatted as [False, "package@version"] or similar
                    fixed_ver = upgrade_path[1].split("@")[-1]
                elif vuln.get("fixedIn"):
                    fixed_in = vuln.get("fixedIn")
                    fixed_ver = fixed_in[0] if isinstance(fixed_in, list) else str(fixed_in)

                finding = Finding(
                    id=f"snyk-{pkg_name}-{vuln_id}",
                    scanner="snyk",
                    finding_type=FindingType.SCA,
                    rule_id=rule_id,
                    title=f"Snyk SCA: {title} in {pkg_name} ({rule_id})",
                    description=desc,
                    severity=severity,
                    cwe_ids=cwe_list or ["CWE-1395"],
                    cvss_score=float(cvss_score) if cvss_score else None,
                    file_path=run.get("displayTargetFile", manifest_path),
                    start_line=1,
                    end_line=1,
                    vulnerable_code=f"{pkg_name}=={pkg_version}",
                    package_name=pkg_name,
                    installed_version=pkg_version,
                    fixed_version=fixed_ver or "latest",
                    references=cve_list
                )
                findings.append(finding)
            except Exception as e:
                logger.warning("Skipping malformed Snyk vulnerability entry: %s", e)
                continue

    logger.info("Successfully parsed %d findings from Snyk report.", len(findings))
    return findings
