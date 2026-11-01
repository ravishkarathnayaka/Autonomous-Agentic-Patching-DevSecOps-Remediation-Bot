"""Parser for Veracode Static Analysis (SAST) JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_veracode_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Veracode SAST JSON report into normalized Finding models.

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
    flaws = data.get("findings", []) if "findings" in data else data.get("flaws", [])

    for flaw in flaws:
        issue_id = str(flaw.get("issue_id", flaw.get("flaw_id", "V-001")))
        cwe_raw = str(flaw.get("cwe_id", "89"))
        cwe_id = f"CWE-{cwe_raw}" if not cwe_raw.startswith("CWE-") else cwe_raw
        title = flaw.get("display_text", f"Veracode Flaw: {cwe_id}")
        desc = flaw.get("description", title)
        
        # Veracode severities: 5=Very High, 4=High, 3=Medium, 2=Low, 1=Info
        sev_num = int(flaw.get("severity", 3))
        if sev_num >= 5:
            severity = SeverityLevel.CRITICAL
            cvss = 9.5
        elif sev_num == 4:
            severity = SeverityLevel.HIGH
            cvss = 7.5
        elif sev_num == 3:
            severity = SeverityLevel.MEDIUM
            cvss = 5.0
        else:
            severity = SeverityLevel.LOW
            cvss = 3.0

        source_file_info = flaw.get("files", {}).get("source_file", {})
        file_path = source_file_info.get("file", flaw.get("file", "app.py"))
        line_num = int(source_file_info.get("line", flaw.get("line", 1)))

        finding = Finding(
            id=f"veracode-{issue_id}",
            scanner="veracode",
            finding_type=FindingType.SAST,
            rule_id=f"veracode.cwe{cwe_raw}",
            title=f"Veracode Security Flaw: {cwe_id}",
            description=desc,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=[cwe_id],
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            vulnerable_code=f"// Veracode Flaw ID {issue_id} at line {line_num}"
        )
        findings.append(finding)

    return findings
