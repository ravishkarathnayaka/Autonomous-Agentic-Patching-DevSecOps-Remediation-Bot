"""Parser for Clang-Tidy C/C++ static analysis diagnostics reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union
import yaml

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_clang_tidy_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Clang-Tidy diagnostic output (JSON or YAML) into normalized Finding models.

    Args:
        report_data: Raw JSON/YAML string, parsed dict, or Path to report file.

    Returns:
        List of normalized Finding models representing C/C++ security issues.
    """
    if isinstance(report_data, Path):
        text = report_data.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = yaml.safe_load(text)
    elif isinstance(report_data, str):
        try:
            data = json.loads(report_data)
        except json.JSONDecodeError:
            data = yaml.safe_load(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    diagnostics = data.get("Diagnostics", data.get("diagnostics", [])) if isinstance(data, dict) else []

    for diag in diagnostics:
        check_name = diag.get("DiagnosticName", diag.get("name", "clang-tidy-check"))
        message_info = diag.get("DiagnosticMessage", diag.get("message", {}))
        if isinstance(message_info, str):
            msg_text = message_info
            file_path = "src/main.cpp"
            line_no = 1
        else:
            msg_text = message_info.get("Message", "Clang-Tidy security check diagnostic")
            file_path = message_info.get("FilePath", "src/main.cpp")
            line_no = int(message_info.get("FileOffset", 1) // 40 + 1) if "FileOffset" in message_info else 1

        # Determine severity based on check category
        if "security." in check_name or "bugprone." in check_name or "cert-" in check_name:
            severity = SeverityLevel.HIGH
            cwe_id = "CWE-119"  # Buffer errors / memory safety
        elif "nullability" in check_name or "use-after-move" in check_name:
            severity = SeverityLevel.HIGH
            cwe_id = "CWE-476"  # NULL pointer dereference
        else:
            severity = SeverityLevel.MEDIUM
            cwe_id = "CWE-676"  # Dangerous functions

        finding = Finding(
            id=f"clang-tidy-{check_name.replace('.', '-')}-{line_no}",
            scanner="clang-tidy",
            finding_type=FindingType.SAST,
            rule_id=check_name,
            title=f"C/C++ Security Flaw: {check_name}",
            description=msg_text,
            severity=severity,
            cwe_ids=[cwe_id],
            cvss_score=7.8 if severity == SeverityLevel.HIGH else 5.0,
            file_path=file_path,
            start_line=line_no,
            end_line=line_no,
            vulnerable_code=f"// Flagged by {check_name}"
        )
        findings.append(finding)

    return findings
