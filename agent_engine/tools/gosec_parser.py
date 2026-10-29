"""Parser for Gosec (Go Security) scanner JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_gosec_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Gosec JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to gosec report file.

    Returns:
        List of normalized Finding models representing Go security vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    issues = data.get("Issues", [])

    for issue in issues:
        rule_id = issue.get("rule_id", "G101")
        details = issue.get("details", "Gosec security finding")
        file_path = issue.get("file", "main.go")
        line_no = int(issue.get("line", 1) or 1)
        code = issue.get("code", "")
        sev_str = issue.get("severity", "MEDIUM").upper()

        if sev_str == "HIGH":
            severity = SeverityLevel.HIGH
        elif sev_str == "LOW":
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_info = issue.get("cwe", {})
        cwe_id = f"CWE-{cwe_info.get('id', '78')}" if isinstance(cwe_info, dict) and "id" in cwe_info else "CWE-78"

        finding = Finding(
            id=f"gosec-{rule_id.lower()}-{line_no}",
            scanner="gosec",
            finding_type=FindingType.SAST,
            rule_id=rule_id,
            title=f"Gosec {rule_id}: {details[:60]}",
            description=details,
            severity=severity,
            cwe_ids=[cwe_id],
            cvss_score=8.2 if severity == SeverityLevel.HIGH else 5.5,
            file_path=file_path,
            start_line=line_no,
            end_line=line_no,
            vulnerable_code=code
        )
        findings.append(finding)

    return findings
