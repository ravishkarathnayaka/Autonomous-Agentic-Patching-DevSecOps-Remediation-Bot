"""Parser for GitGuardian / ggshield secret scan JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_gitguardian_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse GitGuardian (ggshield) JSON scan results into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to ggshield JSON.

    Returns:
        List of normalized Finding models for secret leaks.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    entities = data.get("entities_with_incidents", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for entity in entities:
        filename = entity.get("filename", "target_repo/app.py")
        incidents = entity.get("incidents", [])

        for inc in incidents:
            try:
                detector = inc.get("detector", "generic-secret")
                validity = inc.get("validity", "unknown")
                occurrences = inc.get("occurrences", [])
                line_start = occurrences[0].get("line_start", 1) if occurrences else 1
                line_end = occurrences[0].get("line_end", line_start) if occurrences else line_start

                finding = Finding(
                    id=f"gitguardian-{detector[:12]}-{line_start}",
                    scanner="gitguardian",
                    finding_type=FindingType.SECRET,
                    rule_id=detector,
                    title=f"GitGuardian: Leaked {detector} credential",
                    description=f"Secret token detected ({detector}, validity={validity}) in {filename}",
                    severity=SeverityLevel.CRITICAL if validity == "valid" else SeverityLevel.HIGH,
                    cwe_ids=["CWE-798"],
                    cvss_score=9.0,
                    file_path=filename,
                    start_line=line_start,
                    end_line=line_end,
                    vulnerable_code=f"# Hardcoded secret flagged by GitGuardian detector {detector}",
                    references=[]
                )
                findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse GitGuardian incident: %s", e)
                continue

    logger.info("Successfully parsed %d findings from GitGuardian report.", len(findings))
    return findings
