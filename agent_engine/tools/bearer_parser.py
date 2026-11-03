"""Parser for Bearer CLI security & data privacy static analysis reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_bearer_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Bearer CLI JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing code security & privacy findings.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    # Bearer groups findings by rule_id in 'critical', 'high', 'medium', 'low' or root dictionary
    for sev_key in ["critical", "high", "medium", "low"]:
        rule_list = data.get(sev_key, [])
        for rule_item in rule_list:
            rule_id = rule_item.get("id", "bearer-rule")
            title = rule_item.get("title", rule_id)
            desc = rule_item.get("description", "Vulnerability detected by Bearer SAST.")
            cwe = rule_item.get("cwe_ids", [])
            matches = rule_item.get("matches", [])

            if sev_key == "critical":
                severity = SeverityLevel.CRITICAL
            elif sev_key == "high":
                severity = SeverityLevel.HIGH
            elif sev_key == "low":
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.MEDIUM

            for m in matches:
                file_path = m.get("filename", "src/app.py")
                line = int(m.get("line_number", 1))
                finding = Finding(
                    id=f"bearer-{rule_id}-{file_path}-{line}",
                    scanner="bearer",
                    finding_type=FindingType.SAST,
                    rule_id=rule_id,
                    title=f"Bearer: {title}",
                    description=desc,
                    severity=severity,
                    cwe_ids=cwe if isinstance(cwe, list) else [cwe],
                    file_path=file_path,
                    start_line=line,
                    end_line=line,
                )
                findings.append(finding)

    return findings
