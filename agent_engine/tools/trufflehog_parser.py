"""Parser for TruffleHog v3 secret scan JSON/JSONL reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_trufflehog_report(report_data: Union[str, Dict[str, Any], List[Any], Path]) -> List[Finding]:
    """Parse TruffleHog v3 JSON/JSONL scan report into normalized Finding models.

    Args:
        report_data: Raw JSON/JSONL string, parsed dict/list, or Path to report file.

    Returns:
        List of normalized Finding models for secret leaks.
    """
    entries = []
    if isinstance(report_data, Path):
        text = report_data.read_text(encoding="utf-8")
        for line in text.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    elif isinstance(report_data, str):
        for line in report_data.strip().splitlines():
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    elif isinstance(report_data, list):
        entries = report_data
    elif isinstance(report_data, dict):
        entries = [report_data]

    findings: List[Finding] = []

    for item in entries:
        try:
            detector_name = item.get("DetectorName", "TruffleHogSecret")
            verified = item.get("Verified", False)
            source_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
            file_path = source_meta.get("file", "target_repo/app.py")
            line_no = int(source_meta.get("line", 1) or 1)

            severity = SeverityLevel.CRITICAL if verified else SeverityLevel.HIGH

            finding = Finding(
                id=f"trufflehog-{detector_name.lower()}-{line_no}",
                scanner="trufflehog",
                finding_type=FindingType.SECRET,
                rule_id=detector_name,
                title=f"TruffleHog: Leaked {detector_name} {'(VERIFIED ACTIVE)' if verified else ''}".strip(),
                description=f"Secret token detected by TruffleHog detector '{detector_name}' in {file_path}",
                severity=severity,
                cwe_ids=["CWE-798"],
                cvss_score=9.8 if verified else 8.5,
                file_path=file_path,
                start_line=line_no,
                end_line=line_no,
                vulnerable_code=f"# Leaked secret detected by {detector_name}",
                references=["https://github.com/trufflesecurity/trufflehog"]
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse TruffleHog entry: %s", e)
            continue

    logger.info("Successfully parsed %d findings from TruffleHog report.", len(findings))
    return findings
