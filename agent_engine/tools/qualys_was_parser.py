"""Parser for Qualys Web Application Scanning (WAS) vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_qualys_was_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Qualys WAS JSON export into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing dynamic web vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    vuln_list = data.get("findings", []) if "findings" in data else data.get("web_application_findings", [])

    for idx, vuln in enumerate(vuln_list, start=1):
        qid = str(vuln.get("qid", f"QUALYS-{idx}"))
        name = vuln.get("name", vuln.get("title", "Qualys-Finding"))
        desc = vuln.get("description", "Vulnerability detected by Qualys Web Application Scanning.")
        url_path = vuln.get("url", "/api/v1/resource")
        cwe = vuln.get("cwe_id", vuln.get("cwe", ""))
        severity_num = int(vuln.get("severity", 3))

        if severity_num >= 5:
            severity = SeverityLevel.CRITICAL
        elif severity_num == 4:
            severity = SeverityLevel.HIGH
        elif severity_num <= 2:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_ids = []
        if cwe:
            cwe_str = str(cwe)
            cwe_ids.append(cwe_str if cwe_str.startswith("CWE-") else f"CWE-{cwe_str}")

        finding = Finding(
            id=f"qualys-{qid}-{idx}",
            scanner="qualys",
            finding_type=FindingType.DAST,
            rule_id=f"QID-{qid}",
            title=f"Qualys WAS: {name} on {url_path}",
            description=desc,
            severity=severity,
            cwe_ids=cwe_ids,
            file_path="target_repo/app.py",
            start_line=1,
            end_line=1,
        )
        findings.append(finding)

    return findings
