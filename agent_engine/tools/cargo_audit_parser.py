"""Parser for Rust Cargo-Audit SCA vulnerability JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_cargo_audit_report(
    report_data: Union[str, Dict[str, Any], Path],
    cargo_lock_path: str = "Cargo.lock"
) -> List[Finding]:
    """Parse cargo-audit JSON output into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.
        cargo_lock_path: Target Cargo lockfile path.

    Returns:
        List of normalized Finding models for Rust package vulnerabilities.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data) if report_data.strip() else {}
    else:
        data = report_data

    vulns = data.get("vulnerabilities", {}).get("list", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for v in vulns:
        try:
            advisory = v.get("advisory", {})
            pkg = v.get("package", {})
            rustsec_id = advisory.get("id", "RUSTSEC-UNKNOWN")
            pkg_name = pkg.get("name", "crate")
            pkg_ver = pkg.get("version", "0.0.0")
            title = advisory.get("title", f"Vulnerability in {pkg_name}")
            desc = advisory.get("description", title)
            cwe = advisory.get("cwe")
            cwe_ids = [f"CWE-{cwe}"] if cwe else ["CWE-1395"]

            versions = v.get("versions", {})
            patched = versions.get("patched", [])
            fixed_version = patched[0] if patched else "latest"

            cvss = advisory.get("cvss")
            cvss_score = float(cvss) if cvss is not None else 7.5

            finding = Finding(
                id=f"cargo-{pkg_name}-{rustsec_id.lower()}",
                scanner="cargo-audit",
                finding_type=FindingType.SCA,
                rule_id=rustsec_id,
                title=f"Cargo-Audit: {pkg_name} {title[:70]}",
                description=desc,
                severity=SeverityLevel.HIGH if cvss_score >= 7.0 else SeverityLevel.MEDIUM,
                cwe_ids=cwe_ids,
                cvss_score=cvss_score,
                file_path=cargo_lock_path,
                start_line=1,
                end_line=1,
                vulnerable_code=f"{pkg_name} = \"{pkg_ver}\"",
                package_name=pkg_name,
                installed_version=pkg_ver,
                fixed_version=fixed_version,
                references=[advisory.get("url")] if advisory.get("url") else []
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse Cargo-audit vulnerability: %s", e)
            continue

    logger.info("Successfully parsed %d findings from Cargo-Audit report.", len(findings))
    return findings
