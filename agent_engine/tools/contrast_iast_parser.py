"""Parser for Contrast Security Interactive Application Security Testing (IAST) reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_contrast_iast_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Contrast Security IAST JSON report into normalized Finding models.

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
    traces = data.get("traces", []) if "traces" in data else data.get("vulnerabilities", [])

    for t in traces:
        rule_name = t.get("rule_name", t.get("rule", "contrast-finding"))
        title = t.get("title", f"Contrast IAST: {rule_name}")
        cwe_raw = str(t.get("cwe", "CWE-89"))
        cwe_id = f"CWE-{cwe_raw}" if not cwe_raw.startswith("CWE-") else cwe_raw
        sev_raw = str(t.get("severity", "MEDIUM")).upper()

        if sev_raw == "CRITICAL":
            severity = SeverityLevel.CRITICAL
            cvss = 9.0
        elif sev_raw == "HIGH":
            severity = SeverityLevel.HIGH
            cvss = 7.5
        elif sev_raw == "LOW":
            severity = SeverityLevel.LOW
            cvss = 3.5
        else:
            severity = SeverityLevel.MEDIUM
            cvss = 5.0

        events = t.get("events", [])
        file_path = "app.py"
        line_num = 1
        if events:
            ev0 = events[0]
            file_path = ev0.get("file_name", file_path)
            line_num = int(ev0.get("line_number", 1))

        finding = Finding(
            id=f"contrast-{rule_name.lower()}-{abs(hash(file_path + str(line_num))) % 10000}",
            scanner="contrast-iast",
            finding_type=FindingType.DAST,
            rule_id=f"contrast.{rule_name.lower().replace(' ', '-')}",
            title=title,
            description=t.get("sub_title", f"Dynamic dataflow trace violation identified by Contrast: {title}"),
            severity=severity,
            cvss_score=cvss,
            cwe_ids=[cwe_id],
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            vulnerable_code=f"// Contrast IAST Trace: {rule_name} at line {line_num}"
        )
        findings.append(finding)

    return findings
