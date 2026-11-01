"""Parser for Micro Focus / OpenText Fortify SSC static analysis reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_fortify_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Fortify Software Security Center (SSC) report JSON into normalized Finding models.

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
    issues = data.get("data", []) if isinstance(data.get("data"), list) else data.get("issues", [])

    for issue in issues:
        issue_name = issue.get("issueName", "Fortify Finding")
        category = issue.get("issueStatus", issue_name)
        friority = str(issue.get("friority", "Medium")).upper()
        file_path = issue.get("fullFileName", issue.get("filePath", "app.py"))
        line_num = int(issue.get("lineNumber", 1))
        brief = issue.get("abstract", f"Security issue detected by Fortify: {issue_name}")
        cwe_raw = issue.get("cwe", "CWE-89")
        cwe_id = f"CWE-{cwe_raw}" if not str(cwe_raw).startswith("CWE-") else str(cwe_raw)

        if friority == "CRITICAL":
            severity = SeverityLevel.CRITICAL
            cvss = 9.0
        elif friority == "HIGH":
            severity = SeverityLevel.HIGH
            cvss = 7.5
        elif friority == "LOW":
            severity = SeverityLevel.LOW
            cvss = 3.0
        else:
            severity = SeverityLevel.MEDIUM
            cvss = 5.0

        finding = Finding(
            id=f"fortify-{abs(hash(issue_name + file_path + str(line_num))) % 100000}",
            scanner="fortify",
            finding_type=FindingType.SAST,
            rule_id=f"fortify.{issue_name.lower().replace(' ', '-')}",
            title=f"Fortify SAST: {issue_name}",
            description=brief,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=[cwe_id],
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            vulnerable_code=f"// Fortify Issue: {issue_name} at line {line_num}"
        )
        findings.append(finding)

    return findings
