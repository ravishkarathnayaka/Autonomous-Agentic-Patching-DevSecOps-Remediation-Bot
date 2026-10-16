"""Parser for Flawfinder C/C++ static analysis security reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_flawfinder_report(report_data: Union[str, Dict[str, Any], List[Any], Path]) -> List[Finding]:
    """Parse Flawfinder JSON/list report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict/list, or Path to JSON file.

    Returns:
        List of normalized Finding models.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data) if report_data.strip() else []
    else:
        data = report_data

    items = data if isinstance(data, list) else data.get("results", [])
    findings: List[Finding] = []

    for item in items:
        try:
            rule_id = item.get("rule_id", item.get("name", "buffer-overflow"))
            level = int(item.get("level", 3) or 3)
            file_path = item.get("file", "native/crypto.c")
            line = int(item.get("line", 1) or 1)
            desc = item.get("warning", "Potential buffer or memory safety flaw")
            cwe = item.get("cwe", "120")

            if level >= 4:
                severity = SeverityLevel.CRITICAL
            elif level == 3:
                severity = SeverityLevel.HIGH
            elif level == 2:
                severity = SeverityLevel.MEDIUM
            else:
                severity = SeverityLevel.LOW

            finding = Finding(
                id=f"flawfinder-{rule_id}-{line}",
                scanner="flawfinder",
                finding_type=FindingType.SAST,
                rule_id=f"FF-{rule_id}",
                title=f"Flawfinder: {desc[:80]}",
                description=desc,
                severity=severity,
                cwe_ids=[f"CWE-{cwe}"],
                cvss_score=8.5 if severity == SeverityLevel.CRITICAL else 7.0,
                file_path=file_path,
                start_line=line,
                end_line=line,
                vulnerable_code=item.get("context", f"# Line {line}"),
                references=["https://dwheeler.com/flawfinder/"]
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse Flawfinder item: %s", e)
            continue

    logger.info("Successfully parsed %d findings from Flawfinder report.", len(findings))
    return findings
