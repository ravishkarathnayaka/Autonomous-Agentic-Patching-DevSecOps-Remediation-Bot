"""Parser for Checkmarx One / CxSAST security vulnerability scan reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_checkmarx_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Checkmarx scan JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to Checkmarx report.

    Returns:
        List of normalized Finding models representing enterprise SAST findings.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    queries = data.get("queries", data.get("results", []))

    for item in queries:
        query_id = item.get("queryId", item.get("id", "Cx-001"))
        query_name = item.get("queryName", item.get("name", "Checkmarx Security Finding"))
        cwe_str = str(item.get("cweId", item.get("cwe", "79")))
        cwe_id = f"CWE-{cwe_str}" if not cwe_str.startswith("CWE-") else cwe_str
        sev_str = str(item.get("severity", "Medium")).upper()

        if sev_str == "HIGH":
            severity = SeverityLevel.HIGH
        elif sev_str == "CRITICAL":
            severity = SeverityLevel.CRITICAL
        elif sev_str == "LOW":
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        results_list = item.get("results", [item])
        for res in results_list:
            file_path = res.get("filename", res.get("sourceFile", "target_repo/app.py"))
            line_no = int(res.get("line", res.get("sourceLine", 1)) or 1)
            snippet = res.get("snippet", f"// Checkmarx finding {query_name}")

            finding = Finding(
                id=f"checkmarx-{query_id.lower()}-{line_no}",
                scanner="checkmarx",
                finding_type=FindingType.SAST,
                rule_id=f"Cx-{query_id}",
                title=f"Checkmarx: {query_name}",
                description=f"Enterprise SAST finding {query_name} ({cwe_id})",
                severity=severity,
                cwe_ids=[cwe_id],
                cvss_score=8.0 if severity in {SeverityLevel.CRITICAL, SeverityLevel.HIGH} else 5.5,
                file_path=file_path,
                start_line=line_no,
                end_line=line_no,
                vulnerable_code=snippet
            )
            findings.append(finding)

    return findings
