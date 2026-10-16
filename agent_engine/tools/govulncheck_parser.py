"""Parser for official Go govulncheck JSON vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_govulncheck_report(
    report_data: Union[str, Dict[str, Any], List[Any], Path],
    go_mod_path: str = "go.mod"
) -> List[Finding]:
    """Parse govulncheck JSON output stream into normalized Finding models.

    Args:
        report_data: Raw JSON or newline-delimited JSON stream from govulncheck -json.
        go_mod_path: Target go.mod path.

    Returns:
        List of normalized Finding models for Go dependency flaws.
    """
    entries = []
    if isinstance(report_data, Path):
        text = report_data.read_text(encoding="utf-8")
        try:
            parsed = json.loads(text)
            entries = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in text.strip().splitlines():
                if line.strip():
                    try:
                        entries.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
    elif isinstance(report_data, str):
        try:
            parsed = json.loads(report_data)
            entries = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in report_data.strip().splitlines():
                if line.strip():
                    try:
                        entries.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
    elif isinstance(report_data, list):
        entries = report_data
    elif isinstance(report_data, dict):
        entries = [report_data]

    findings: List[Finding] = []

    for item in entries:
        osv = item.get("osv")
        if not osv or not isinstance(osv, dict):
            continue

        try:
            vuln_id = osv.get("id", "GO-VULN")
            aliases = osv.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)
            details = osv.get("details", f"Go vulnerability in module {vuln_id}")
            affected = osv.get("affected", [])

            pkg_name = "golang.org/module"
            installed_ver = "v0.0.1"
            fixed_ver = "latest"

            if affected and isinstance(affected[0], dict):
                mod = affected[0].get("package", {})
                pkg_name = mod.get("name", pkg_name)
                ranges = affected[0].get("ranges", [])
                if ranges and "events" in ranges[0]:
                    for ev in ranges[0]["events"]:
                        if "fixed" in ev:
                            fixed_ver = ev["fixed"]
                            break

            finding = Finding(
                id=f"govulncheck-{pkg_name.replace('/', '_')}-{cve_id.lower()}",
                scanner="govulncheck",
                finding_type=FindingType.SCA,
                rule_id=cve_id,
                title=f"govulncheck: {pkg_name} ({cve_id})",
                description=details,
                severity=SeverityLevel.HIGH,
                cwe_ids=["CWE-1395"],
                cvss_score=7.8,
                file_path=go_mod_path,
                start_line=1,
                end_line=1,
                vulnerable_code=f"require {pkg_name} {installed_ver}",
                package_name=pkg_name,
                installed_version=installed_ver,
                fixed_version=fixed_ver,
                references=aliases
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse govulncheck OSV entry: %s", e)
            continue

    logger.info("Successfully parsed %d findings from govulncheck report.", len(findings))
    return findings
