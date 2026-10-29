"""Parser for Anchore Syft SBOM JSON catalog reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_syft_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Syft SBOM catalog JSON into normalized package findings.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to Syft SBOM report.

    Returns:
        List of normalized Finding models representing audited dependencies.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    artifacts = data.get("artifacts", [])

    for art in artifacts:
        name = art.get("name", "unknown")
        version = art.get("version", "0.0.0")
        pkg_type = art.get("type", "generic")
        licenses = art.get("licenses", [])
        lic_names = [l.get("value", "") for l in licenses if isinstance(l, dict)]
        if not lic_names and isinstance(licenses, list):
            lic_names = [str(l) for l in licenses]

        cpe = art.get("cpes", [{}])[0].get("cpe", "") if art.get("cpes") else ""
        locations = art.get("locations", [{}])
        file_path = locations[0].get("path", "requirements.txt") if locations else "package.json"

        finding = Finding(
            id=f"syft-{name.lower()}-{version}",
            scanner="syft",
            finding_type=FindingType.SCA,
            rule_id=f"syft.{pkg_type}.inventory",
            title=f"Inventory Component: {name} v{version}",
            description=f"Package {name} ({pkg_type}) detected. Licenses: {', '.join(lic_names) or 'None'}. CPE: {cpe}",
            severity=SeverityLevel.LOW,
            cwe_ids=["CWE-1395"],
            cvss_score=3.1,
            file_path=file_path,
            start_line=1,
            end_line=1,
            package_name=name,
            installed_version=version,
            fixed_version=None,
            vulnerable_code=f"{name}=={version}"
        )
        findings.append(finding)

    return findings
