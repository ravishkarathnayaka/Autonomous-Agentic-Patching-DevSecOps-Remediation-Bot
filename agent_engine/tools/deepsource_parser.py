"""Parser for DeepSource static code analysis and security findings."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_deepsource_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse DeepSource JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing SAST security issues.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    issues = data.get("issues", []) if isinstance(data, dict) else []

    for idx, item in enumerate(issues, start=1):
        issue_code = item.get("issue_code", item.get("code", f"DS-{idx}"))
        title = item.get("title", item.get("message", "DeepSource Security Issue"))
        description = item.get("description", title)
        file_path = item.get("path", item.get("file", "unknown"))
        line = int(item.get("line", item.get("begin_line", 1)))
        sev_raw = str(item.get("severity", "major")).lower()
        cwe = item.get("cwe", "")

        if sev_raw in ["critical", "blocker"]:
            severity = SeverityLevel.CRITICAL
        elif sev_raw in ["major", "high"]:
            severity = SeverityLevel.HIGH
        elif sev_raw in ["minor", "low", "info"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_list = [cwe] if cwe and cwe.startswith("CWE-") else ["CWE-20"]

        findings.append(
            Finding(
                id=f"deepsource-{issue_code}-{idx}",
                scanner="deepsource",
                finding_type=FindingType.SAST,
                rule_id=issue_code,
                title=title,
                description=description,
                severity=severity,
                cwe_ids=cwe_list,
                file_path=file_path,
                start_line=line,
                end_line=line,
                vulnerable_code=item.get("snippet", ""),
                references=[f"https://deepsource.io/directory/analyzers/python/issues/{issue_code}"],
            )
        )

    return findings
