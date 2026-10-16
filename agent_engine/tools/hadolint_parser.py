"""Parser for Hadolint Dockerfile linter JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

HADOLINT_LEVEL_MAP = {
    "error": SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "info": SeverityLevel.LOW,
    "style": SeverityLevel.INFO,
}


def parse_hadolint_report(
    report_data: Union[str, List[Any], Path],
    dockerfile_path: str = "docker/sandbox.Dockerfile"
) -> List[Finding]:
    """Parse Hadolint JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed list of items, or Path to JSON file.
        dockerfile_path: Target Dockerfile path.

    Returns:
        List of normalized Finding models for Dockerfile lints.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data) if report_data.strip() else []
    else:
        data = report_data

    items = data if isinstance(data, list) else []
    findings: List[Finding] = []

    for item in items:
        try:
            code = item.get("code", "DL3000")
            level = str(item.get("level", "warning")).lower()
            severity = HADOLINT_LEVEL_MAP.get(level, SeverityLevel.MEDIUM)
            message = item.get("message", "Dockerfile lint issue")
            line = int(item.get("line", 1) or 1)
            file_name = item.get("file", dockerfile_path)

            cwe_ids = ["CWE-250"] if code == "DL3002" else ["CWE-710"]

            finding = Finding(
                id=f"hadolint-{code.lower()}-{line}",
                scanner="hadolint",
                finding_type=FindingType.IAC,
                rule_id=code,
                title=f"Hadolint: {code} {message[:70]}",
                description=f"Hadolint rule {code} (level={level}): {message}",
                severity=severity,
                cwe_ids=cwe_ids,
                cvss_score=7.0 if severity == SeverityLevel.HIGH else 4.0,
                file_path=file_name,
                start_line=line,
                end_line=line,
                vulnerable_code=f"# Flagged Dockerfile line {line}",
                references=[f"https://github.com/hadolint/hadolint/wiki/{code}"]
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse Hadolint lint item: %s", e)
            continue

    logger.info("Successfully parsed %d findings from Hadolint report.", len(findings))
    return findings
