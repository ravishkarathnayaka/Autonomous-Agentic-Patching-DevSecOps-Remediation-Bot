"""Parser for Horusec multi-language SAST JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

HORUSEC_SEV_MAP = {
    "CRITICAL": SeverityLevel.CRITICAL,
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "INFO": SeverityLevel.INFO,
}


def parse_horusec_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Horusec JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to Horusec output JSON.

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

    vuln_entries = data.get("analysisVulnerabilities", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for entry in vuln_entries:
        try:
            v = entry.get("vulnerabilities", {})
            rule_id = v.get("rule_id", "horusec-vuln")
            details = v.get("details", "Security vulnerability flagged by Horusec")
            raw_sev = str(v.get("severity", "MEDIUM")).upper()
            severity = HORUSEC_SEV_MAP.get(raw_sev, SeverityLevel.MEDIUM)
            file_path = v.get("file", "target_repo/app.py")
            line = int(v.get("line", 1) or 1)
            code = v.get("code", "")
            vuln_type = v.get("type", "Vulnerability")

            finding = Finding(
                id=f"horusec-{rule_id[:8]}-{line}",
                scanner="horusec",
                finding_type=FindingType.SAST,
                rule_id=rule_id,
                title=f"Horusec: {details[:80]}",
                description=details,
                severity=severity,
                cwe_ids=["CWE-20"],
                cvss_score=8.0 if severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH) else 5.0,
                file_path=file_path,
                start_line=line,
                end_line=line,
                vulnerable_code=code or f"# Line {line}",
                references=[]
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Failed to parse Horusec vulnerability entry: %s", e)
            continue

    logger.info("Successfully parsed %d findings from Horusec report.", len(findings))
    return findings
