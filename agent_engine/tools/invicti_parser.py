"""Parser for Invicti (formerly Netsparker) Enterprise DAST scan reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_invicti_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Invicti DAST JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing dynamic application vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    vuln_list = data.get("vulnerabilities", []) if "vulnerabilities" in data else data.get("Vulnerabilities", [])

    for idx, vuln in enumerate(vuln_list, start=1):
        vuln_type = vuln.get("type", vuln.get("Title", "Invicti-Vulnerability"))
        desc = vuln.get("description", vuln.get("Overview", "Vulnerability detected by Invicti DAST."))
        sev_raw = str(vuln.get("severity", vuln.get("Severity", "Medium"))).upper()
        target_url = vuln.get("url", vuln.get("Url", "/"))
        param = vuln.get("parameter", vuln.get("Parameter", ""))
        cwe_raw = vuln.get("cwe", vuln.get("Cwe", ""))

        if sev_raw in ["CRITICAL", "BEST"]:
            severity = SeverityLevel.CRITICAL
        elif sev_raw in ["HIGH", "IMPORTANT"]:
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFORMATION"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_ids: List[str] = []
        if isinstance(cwe_raw, str) and cwe_raw:
            cwe_ids = [cwe_raw if cwe_raw.startswith("CWE-") else f"CWE-{cwe_raw}"]
        elif isinstance(cwe_raw, list):
            cwe_ids = [c if str(c).startswith("CWE-") else f"CWE-{c}" for c in cwe_raw]

        finding = Finding(
            id=f"invicti-{vuln_type.lower().replace(' ', '-')}-{idx}",
            scanner="invicti",
            finding_type=FindingType.DAST,
            rule_id=vuln_type,
            title=f"Invicti: {vuln_type} on {target_url}" + (f" ({param})" if param else ""),
            description=desc,
            severity=severity,
            cwe_ids=cwe_ids,
            file_path="target_repo/app.py",
            start_line=1,
            end_line=1,
        )
        findings.append(finding)

    return findings
