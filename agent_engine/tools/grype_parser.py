"""Parser for normalizing Anchore Grype container and dependency vulnerability scan reports into Finding models."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from agent_engine.state import Finding, FindingType, SeverityLevel


def _map_grype_severity(raw_severity: str) -> SeverityLevel:
    """Map Grype severity (Critical, High, Medium, Low, Negligible, Unknown) to SeverityLevel."""
    s = (raw_severity or "").strip().upper()
    if s == "CRITICAL":
        return SeverityLevel.CRITICAL
    if s == "HIGH":
        return SeverityLevel.HIGH
    if s == "MEDIUM":
        return SeverityLevel.MEDIUM
    if s == "LOW":
        return SeverityLevel.LOW
    if s in ("NEGLIGIBLE", "INFO", "UNKNOWN"):
        return SeverityLevel.INFO
    return SeverityLevel.MEDIUM


def parse_grype_report(data: Dict[str, Any]) -> List[Finding]:
    """Parse Grype JSON output into normalized Finding objects."""
    findings: List[Finding] = []
    matches = data.get("matches", [])

    for match in matches:
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vuln_id = vuln.get("id", "CVE-UNKNOWN")
        severity_str = vuln.get("severity", "Medium")
        severity = _map_grype_severity(severity_str)
        desc = vuln.get("description", f"Vulnerability {vuln_id} detected.")

        pkg_name = artifact.get("name", "unknown-pkg")
        installed_ver = artifact.get("version", "0.0.0")

        # Fix version
        fix_info = vuln.get("fix", {})
        fix_versions = fix_info.get("versions", [])
        fixed_ver = fix_versions[0] if fix_versions else None

        # Locations
        locations = artifact.get("locations", [])
        path = locations[0].get("path", "requirements.txt") if locations else "requirements.txt"

        # CVSS Score
        cvss_score: Optional[float] = None
        cvss_list = vuln.get("cvss", [])
        if cvss_list and isinstance(cvss_list, list):
            for c in cvss_list:
                metrics = c.get("metrics", {})
                score = metrics.get("baseScore")
                if score is not None:
                    try:
                        cvss_score = float(score)
                        break
                    except (ValueError, TypeError):
                        pass

        # References
        references = vuln.get("urls", [])
        data_source = vuln.get("dataSource")
        if data_source and data_source not in references:
            references.append(data_source)

        cwe_ids: List[str] = []
        related = match.get("relatedVulnerabilities", [])
        for rel in related:
            for cwe in rel.get("cweIds", []):
                clean = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
                if clean not in cwe_ids:
                    cwe_ids.append(clean)

        finding_id = f"grype-{vuln_id.lower()}-{uuid.uuid4().hex[:8]}"

        finding = Finding(
            id=finding_id,
            scanner="grype",
            finding_type=FindingType.CONTAINER,
            rule_id=vuln_id,
            title=f"Vulnerable package {pkg_name} ({vuln_id})",
            description=desc,
            severity=severity,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            file_path=path,
            start_line=1,
            end_line=1,
            vulnerable_code=f"{pkg_name}=={installed_ver}",
            package_name=pkg_name,
            installed_version=installed_ver,
            fixed_version=fixed_ver,
            references=references
        )
        findings.append(finding)

    return findings
