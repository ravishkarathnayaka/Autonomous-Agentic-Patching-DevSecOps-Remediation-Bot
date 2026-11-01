"""Parser for PyLint Security static AST analysis JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_pylint_security_report(report_data: Union[str, Dict[str, Any], Path, List[Dict[str, Any]]]) -> List[Finding]:
    """Parse PyLint Security JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict/list, or Path to JSON file.

    Returns:
        List of normalized Finding models.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    items: List[Dict[str, Any]] = data if isinstance(data, list) else data.get("messages", [])
    findings: List[Finding] = []

    for item in items:
        symbol = item.get("symbol", "pylint-security-warning")
        msg_id = item.get("message-id", "W0000")
        msg = item.get("message", "Security-relevant code pattern detected by PyLint.")
        file_path = item.get("path", "app.py")
        line_num = int(item.get("line", 1))
        msg_type = str(item.get("type", "warning")).lower()

        if msg_type in ["error", "fatal"]:
            severity = SeverityLevel.HIGH
            cvss = 7.5
        elif msg_type == "warning":
            severity = SeverityLevel.MEDIUM
            cvss = 5.0
        else:
            severity = SeverityLevel.LOW
            cvss = 3.0

        # Mapping common dangerous symbols to CWE
        cwe_id = "CWE-95" if "eval" in symbol.lower() else ("CWE-78" if "subprocess" in symbol.lower() else "CWE-693")

        finding = Finding(
            id=f"pylint-{msg_id.lower()}-{abs(hash(file_path + str(line_num))) % 10000}",
            scanner="pylint-security",
            finding_type=FindingType.SAST,
            rule_id=f"pylint.{symbol}",
            title=f"PyLint Security: {symbol} ({msg_id})",
            description=msg,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=[cwe_id],
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            vulnerable_code=f"# PyLint {symbol}: line {line_num}"
        )
        findings.append(finding)

    return findings
