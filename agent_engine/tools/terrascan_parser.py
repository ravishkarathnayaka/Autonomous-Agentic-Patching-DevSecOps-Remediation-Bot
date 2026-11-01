"""Parser for Tenable Terrascan Infrastructure-as-Code security scanner reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_terrascan_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Terrascan IaC report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing IaC misconfigurations.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    results = data.get("results", {})
    violations = results.get("violations", [])

    for v in violations:
        rule_name = v.get("rule_name", "AC_TERRASCAN_GENERIC")
        rule_id = v.get("rule_id", rule_name)
        desc = v.get("description", "Terrascan IaC policy violation.")
        file_path = v.get("file", "main.tf")
        line_num = int(v.get("line_number", 1))
        severity_str = v.get("severity", "MEDIUM").upper()

        if severity_str == "HIGH":
            severity = SeverityLevel.HIGH
        elif severity_str == "LOW":
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        resource_name = v.get("resource_name", "")
        resource_type = v.get("resource_type", "")

        finding = Finding(
            id=f"terrascan-{rule_id.lower()}-{abs(hash(file_path + str(line_num))) % 10000}",
            scanner="terrascan",
            finding_type=FindingType.IAC,
            rule_id=rule_id,
            title=f"IaC Misconfiguration: {rule_name}",
            description=desc,
            severity=severity,
            cvss_score=6.0 if severity == SeverityLevel.HIGH else 4.0,
            cwe_ids=["CWE-16"],
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            vulnerable_code=f"Resource: {resource_type}.{resource_name}"
        )
        findings.append(finding)

    return findings
