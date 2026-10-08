"""Parser for Bandit Python SAST security scanner reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding

logger = logging.getLogger(__name__)


def parse_bandit_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Bandit JSON report data and normalize into list of Finding objects.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

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

    findings: List[Finding] = []
    results = data.get("results", [])

    for idx, item in enumerate(results):
        try:
            test_id = item.get("test_id", f"bandit-{idx}")
            test_name = item.get("test_name", "bandit_issue")
            rule_id = f"bandit.{test_id}.{test_name}"

            # Map severity
            bandit_sev = item.get("issue_severity", "MEDIUM").upper()
            severity_map = {
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "LOW": "LOW",
                "CRITICAL": "CRITICAL"
            }
            severity = severity_map.get(bandit_sev, "MEDIUM")

            # Extract CWE
            cwe_obj = item.get("issue_cwe", {})
            cwe_id = cwe_obj.get("id") if isinstance(cwe_obj, dict) else None
            cwe_list = [f"CWE-{cwe_id}"] if cwe_id else ["CWE-UNKNOWN"]

            # Map CVSS estimate based on severity
            cvss_map = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.5}
            cvss = cvss_map.get(severity, 5.0)

            line_num = item.get("line_number", 1)
            line_range = item.get("line_range", [line_num])
            start_line = line_range[0] if line_range else line_num
            end_line = line_range[-1] if line_range else line_num

            file_path = item.get("filename", "")
            # Normalize path relative to project
            clean_path = file_path.replace("\\", "/").lstrip("./")

            finding = Finding(
                id=f"bandit-{test_id}-{clean_path}-{start_line}",
                scanner="bandit",
                type="SAST",
                rule_id=rule_id,
                title=item.get("issue_text", f"Bandit finding {test_id}"),
                description=item.get("issue_text", "") + f" (Rule: {test_name})",
                severity=severity,
                cwe=cwe_list,
                cvss=cvss,
                file_path=clean_path,
                start_line=start_line,
                end_line=end_line,
                vulnerable_code=item.get("code", "").strip()
            )
            findings.append(finding)
        except Exception as e:
            logger.warning(f"Failed to parse Bandit finding item {idx}: {e}")
            continue

    logger.info(f"Parsed {len(findings)} findings from Bandit report.")
    return findings
