"""Parser for Invicti Acunetix 360 web vulnerability scan reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_acunetix_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Acunetix 360 JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing dynamic application findings.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    vuln_list = data.get("Vulnerabilities", []) if "Vulnerabilities" in data else data.get("vulnerabilities", [])

    for idx, vuln in enumerate(vuln_list, start=1):
        vuln_type = vuln.get("Type", vuln.get("Name", "Acunetix-Vulnerability"))
        desc = vuln.get("Description", "Vulnerability detected by Acunetix 360.")
        sev_raw = str(vuln.get("Severity", "Medium")).upper()
        target_url = vuln.get("Url", vuln.get("Uri", "/api/v1"))
        cwe = vuln.get("Cwe", "")

        if sev_raw in ["CRITICAL", "BEST"]:
            severity = SeverityLevel.CRITICAL
        elif sev_raw in ["HIGH", "IMPORTANT"]:
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFORMATION"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_ids: List[str] = []
        if isinstance(cwe, str) and cwe:
            cwe_ids = [cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"]
        elif isinstance(cwe, list):
            cwe_ids = [c if str(c).startswith("CWE-") else f"CWE-{c}" for c in cwe]

        finding = Finding(
            id=f"acunetix-{vuln_type.lower().replace(' ', '-')}-{idx}",
            scanner="acunetix",
            finding_type=FindingType.DAST,
            rule_id=vuln_type,
            title=f"Acunetix: {vuln_type} at {target_url}",
            description=desc,
            severity=severity,
            cwe_ids=cwe_ids,
            file_path="target_repo/app.py",
            start_line=1,
            end_line=1,
        )
        findings.append(finding)

    return findings
