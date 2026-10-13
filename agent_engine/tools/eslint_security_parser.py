"""Parser for ESLint (eslint-plugin-security) JavaScript / TypeScript SAST JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_eslint_security_report(report_data: Union[str, List[Any], Path]) -> List[Finding]:
    """Parse ESLint JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed list of files, or Path to JSON file.

    Returns:
        List of normalized Finding models.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    file_results = data if isinstance(data, list) else []
    findings: List[Finding] = []

    for file_obj in file_results:
        file_path = file_obj.get("filePath", "web/src/App.tsx")
        messages = file_obj.get("messages", [])

        for msg in messages:
            rule_id = msg.get("ruleId", "security-rule")
            severity_num = msg.get("severity", 1)  # 1 = warning, 2 = error
            message_text = msg.get("message", "Security rule violation")
            line = msg.get("line", 1)
            end_line = msg.get("endLine", line)

            # Map ESLint security rules to CWE
            cwe_ids = ["CWE-95"] if "eval" in rule_id else (["CWE-78"] if "child-process" in rule_id else ["CWE-20"])
            severity = SeverityLevel.HIGH if severity_num == 2 else SeverityLevel.MEDIUM

            finding = Finding(
                id=f"eslint-{rule_id}-{line}",
                scanner="eslint-security",
                finding_type=FindingType.SAST,
                rule_id=rule_id,
                title=f"ESLint Security: {rule_id}",
                description=message_text,
                severity=severity,
                cwe_ids=cwe_ids,
                cvss_score=7.0 if severity == SeverityLevel.HIGH else 4.5,
                file_path=file_path,
                start_line=line,
                end_line=end_line,
                vulnerable_code=f"# Flagged line {line}: {message_text}",
                references=[]
            )
            findings.append(finding)

    logger.info("Successfully parsed %d findings from ESLint Security report.", len(findings))
    return findings
