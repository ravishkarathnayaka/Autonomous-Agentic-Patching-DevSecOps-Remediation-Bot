"""Parser for CycloneDX 1.5 JSON SBOM vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_cyclonedx_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse CycloneDX 1.5 JSON SBOM report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing supply chain vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    vulnerabilities = data.get("vulnerabilities", [])

    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "CVE-UNKNOWN")
        desc = vuln.get("description", "Vulnerability detected in CycloneDX SBOM component.")
        
        # Extract ratings
        ratings = vuln.get("ratings", [])
        severity_str = "MEDIUM"
        cvss_score = 5.0
        if ratings:
            r0 = ratings[0]
            severity_str = r0.get("severity", "medium").upper()
            cvss_score = float(r0.get("score", 5.0))

        if severity_str in ["CRITICAL"]:
            severity = SeverityLevel.CRITICAL
        elif severity_str in ["HIGH"]:
            severity = SeverityLevel.HIGH
        elif severity_str in ["LOW"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwes: List[str] = []
        for cwe_id in vuln.get("cwes", []):
            cwes.append(f"CWE-{cwe_id}" if not str(cwe_id).startswith("CWE-") else str(cwe_id))

        # Target affected component
        affects = vuln.get("affects", [])
        ref = affects[0].get("ref", "root-project") if affects else "root-project"

        finding = Finding(
            id=f"cyclonedx-{vuln_id.lower()}",
            scanner="cyclonedx",
            finding_type=FindingType.SCA,
            rule_id=vuln_id,
            title=f"Supply Chain Advisory: {vuln_id}",
            description=desc,
            severity=severity,
            cvss_score=cvss_score,
            cwe_ids=cwes or ["CWE-1395"],
            file_path="requirements.txt",
            start_line=1,
            end_line=1,
            vulnerable_code=f"Component ref: {ref}"
        )
        findings.append(finding)

    return findings
