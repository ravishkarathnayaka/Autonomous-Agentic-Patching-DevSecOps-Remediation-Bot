"""Parser for Semgrep OSS Secrets detection reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_semgrep_secrets_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Semgrep Secrets scan report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing leaked secrets.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    results = data.get("results", [])

    for r in results:
        check_id = r.get("check_id", "semgrep.secrets.generic")
        path = r.get("path", "")
        start = r.get("start", {})
        end = r.get("end", {})
        start_line = int(start.get("line", 1))
        end_line = int(end.get("line", start_line))

        extra = r.get("extra", {})
        message = extra.get("message", "Leaked secret detected in source code.")
        severity_raw = extra.get("severity", "ERROR").upper()

        if severity_raw == "ERROR":
            severity = SeverityLevel.CRITICAL
        elif severity_raw == "WARNING":
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.MEDIUM

        vulnerable_code = extra.get("lines", "")

        finding = Finding(
            id=f"semgrep-secrets-{abs(hash(check_id + path + str(start_line))) % 100000}",
            scanner="semgrep-secrets",
            finding_type=FindingType.SECRET,
            rule_id=check_id,
            title=f"Exposed Secret: {check_id.split('.')[-1]}",
            description=message,
            severity=severity,
            cwe_ids=["CWE-798"],
            cvss_score=8.5 if severity == SeverityLevel.CRITICAL else 7.0,
            file_path=path,
            start_line=start_line,
            end_line=end_line,
            vulnerable_code=vulnerable_code
        )
        findings.append(finding)

    return findings
