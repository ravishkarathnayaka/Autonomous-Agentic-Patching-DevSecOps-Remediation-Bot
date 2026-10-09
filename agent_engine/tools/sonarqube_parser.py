"""Parser for SonarQube / SonarCloud issue and security hotspot JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

SONAR_SEVERITY_MAP = {
    "BLOCKER": SeverityLevel.CRITICAL,
    "CRITICAL": SeverityLevel.HIGH,
    "MAJOR": SeverityLevel.MEDIUM,
    "MINOR": SeverityLevel.LOW,
    "INFO": SeverityLevel.LOW,
}


def parse_sonarqube_report(
    report_data: Union[str, Dict[str, Any], Path]
) -> List[Finding]:
    """Parse SonarQube issues export (/api/issues/search) into normalized Finding models.

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

    issues = data.get("issues", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for issue in issues:
        try:
            issue_key = issue.get("key", "sonar-issue")
            rule = issue.get("rule", "unknown-rule")
            raw_sev = str(issue.get("severity", "MAJOR")).upper()
            severity = SONAR_SEVERITY_MAP.get(raw_sev, SeverityLevel.MEDIUM)
            message = issue.get("message", "SonarQube code finding")
            
            # Component is usually formatted as "project_key:path/to/file.py"
            raw_comp = issue.get("component", "unknown_file")
            file_path = raw_comp.split(":")[-1] if ":" in raw_comp else raw_comp

            line = issue.get("line", 1)
            issue_type = issue.get("type", "VULNERABILITY").upper()

            # Map SonarQube rule IDs to common CWE IDs if known
            cwe_ids: List[str] = []
            if "S2077" in rule or "sql" in rule.lower():
                cwe_ids = ["CWE-89"]
            elif "S2083" in rule or "path" in rule.lower():
                cwe_ids = ["CWE-22"]
            elif "S5144" in rule or "xss" in rule.lower():
                cwe_ids = ["CWE-79"]
            elif "S4721" in rule or "command" in rule.lower():
                cwe_ids = ["CWE-78"]
            else:
                cwe_ids = ["CWE-20"]

            finding = Finding(
                id=f"sonar-{issue_key}",
                scanner="sonarqube",
                finding_type=FindingType.SAST,
                rule_id=rule,
                title=f"SonarQube: {message}",
                description=f"SonarQube rule {rule} ({issue_type}): {message}",
                severity=severity,
                cwe_ids=cwe_ids,
                cvss_score=8.5 if severity == SeverityLevel.CRITICAL else (7.0 if severity == SeverityLevel.HIGH else 5.0),
                file_path=file_path,
                start_line=line,
                end_line=line,
                vulnerable_code=f"# Issue at line {line}: {message}",
                references=[f"https://rules.sonarsource.com/rule/{rule}"]
            )
            findings.append(finding)
        except Exception as e:
            logger.warning("Skipping malformed SonarQube issue: %s", e)
            continue

    logger.info("Parsed %d issues from SonarQube report.", len(findings))
    return findings
