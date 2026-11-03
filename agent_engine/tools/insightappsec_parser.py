"""Parser for Rapid7 InsightAppSec dynamic application security testing reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_insightappsec_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Rapid7 InsightAppSec JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing DAST findings.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    vulnerabilities = data.get("vulnerabilities", []) if "vulnerabilities" in data else data.get("data", [])

    for idx, vuln in enumerate(vulnerabilities, start=1):
        vuln_type = vuln.get("vuln_type", vuln.get("name", "InsightAppSec-Vulnerability"))
        desc = vuln.get("description", "Vulnerability detected by Rapid7 InsightAppSec.")
        sev_raw = str(vuln.get("severity", "MEDIUM")).upper()
        vector = vuln.get("vector", {})
        url_path = vector.get("url", vuln.get("url", "/api/v1/storage"))
        param = vector.get("parameter", vuln.get("parameter", ""))
        cwe = vuln.get("cwe", "")

        if sev_raw in ["CRITICAL", "VERY_HIGH"]:
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH":
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "INFORMATIONAL"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_ids: List[str] = []
        if isinstance(cwe, str) and cwe:
            cwe_ids = [cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"]
        elif isinstance(cwe, list):
            cwe_ids = [c if str(c).startswith("CWE-") else f"CWE-{c}" for c in cwe]

        finding = Finding(
            id=f"insightappsec-{vuln_type.lower().replace(' ', '-')}-{idx}",
            scanner="insightappsec",
            finding_type=FindingType.DAST,
            rule_id=vuln_type,
            title=f"InsightAppSec: {vuln_type} at {url_path}" + (f" ({param})" if param else ""),
            description=desc,
            severity=severity,
            cwe_ids=cwe_ids,
            file_path="target_repo/app.py",
            start_line=1,
            end_line=1,
        )
        findings.append(finding)

    return findings
