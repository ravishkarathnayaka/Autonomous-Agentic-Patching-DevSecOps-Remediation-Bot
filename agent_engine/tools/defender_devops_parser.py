"""Parser for Microsoft Defender for DevOps security scan reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_defender_devops_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Microsoft Defender for DevOps report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    runs = data.get("runs", [])
    results = runs[0].get("results", []) if runs else data.get("results", [])

    for r in results:
        rule_id = r.get("ruleId", "Defender.Security.Generic")
        msg = r.get("message", {}).get("text", "Security violation reported by Defender for DevOps.")
        level = str(r.get("level", "warning")).lower()

        if level == "error":
            severity = SeverityLevel.HIGH
            cvss = 7.5
        elif level == "warning":
            severity = SeverityLevel.MEDIUM
            cvss = 5.0
        else:
            severity = SeverityLevel.LOW
            cvss = 3.0

        locations = r.get("locations", [])
        file_path = "app.py"
        line_num = 1
        if locations:
            phys = locations[0].get("physicalLocation", {})
            file_path = phys.get("artifactLocation", {}).get("uri", "app.py")
            line_num = int(phys.get("region", {}).get("startLine", 1))

        cwe_id = "CWE-89" if "sql" in rule_id.lower() else ("CWE-798" if "secret" in rule_id.lower() else "CWE-693")

        finding = Finding(
            id=f"defender-{rule_id.lower()}-{abs(hash(file_path + str(line_num))) % 10000}",
            scanner="defender-devops",
            finding_type=FindingType.SAST,
            rule_id=rule_id,
            title=f"Defender for DevOps: {rule_id}",
            description=msg,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=[cwe_id],
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            vulnerable_code=f"// Defender for DevOps Finding: {rule_id} at line {line_num}"
        )
        findings.append(finding)

    return findings
