"""Parser for Synopsys Black Duck Software Composition Analysis (SCA) reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_blackduck_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Synopsys Black Duck SCA report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing open source vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    items = data.get("items", []) if "items" in data else data.get("vulnerabilities", [])

    for item in items:
        vuln_name = item.get("vulnerabilityName", "BDSA-UNKNOWN")
        desc = item.get("description", "Open source dependency flaw identified by Black Duck.")
        score = float(item.get("baseScore", 5.0))
        sev_raw = str(item.get("severity", "MEDIUM")).upper()

        if sev_raw == "CRITICAL" or score >= 9.0:
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or score >= 7.0:
            severity = SeverityLevel.HIGH
        elif sev_raw == "LOW" or score < 4.0:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        component = item.get("componentName", "dependency")
        version = item.get("componentVersionName", "0.0.0")
        cwe_raw = str(item.get("cweId", "CWE-1395"))
        cwe_id = f"CWE-{cwe_raw}" if not cwe_raw.startswith("CWE-") else cwe_raw

        finding = Finding(
            id=f"blackduck-{vuln_name.lower()}-{component}",
            scanner="blackduck",
            finding_type=FindingType.SCA,
            rule_id=vuln_name,
            title=f"Black Duck Vulnerability: {component} ({vuln_name})",
            description=desc,
            severity=severity,
            cvss_score=score,
            cwe_ids=[cwe_id],
            file_path="requirements.txt",
            start_line=1,
            end_line=1,
            vulnerable_code=f"{component}=={version}"
        )
        findings.append(finding)

    return findings
