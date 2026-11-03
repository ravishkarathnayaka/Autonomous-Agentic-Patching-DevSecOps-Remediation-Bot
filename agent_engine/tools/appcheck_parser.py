"""Parser for AppCheck web application vulnerability scanner reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_appcheck_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse AppCheck JSON report into normalized Finding models.

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
    vuln_list = data.get("vulnerabilities", []) if "vulnerabilities" in data else data.get("alerts", [])

    for idx, vuln in enumerate(vuln_list, start=1):
        vuln_name = vuln.get("name", vuln.get("title", "AppCheck-Vulnerability"))
        desc = vuln.get("description", "Vulnerability detected by AppCheck DAST engine.")
        sev_raw = str(vuln.get("severity", "Medium")).upper()
        url_path = vuln.get("url", vuln.get("path", "/api/v1/resource"))
        param = vuln.get("parameter", "")
        cvss = float(vuln.get("cvss", vuln.get("cvss_score", 5.0)))
        cwe = vuln.get("cwe", "")

        if sev_raw == "CRITICAL" or cvss >= 9.0:
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH" or cvss >= 7.0:
            severity = SeverityLevel.HIGH
        elif sev_raw == "LOW" or cvss < 4.0:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_ids = [cwe] if isinstance(cwe, str) and cwe else (cwe if isinstance(cwe, list) else [])

        finding = Finding(
            id=f"appcheck-{vuln_name.lower().replace(' ', '-')}-{idx}",
            scanner="appcheck",
            finding_type=FindingType.DAST,
            rule_id=vuln_name,
            title=f"AppCheck: {vuln_name} at {url_path}" + (f" (param: {param})" if param else ""),
            description=desc,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=cwe_ids,
            file_path="target_repo/app.py",
            start_line=1,
            end_line=1,
        )
        findings.append(finding)

    return findings
