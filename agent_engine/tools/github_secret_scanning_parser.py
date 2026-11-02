"""Parser for GitHub Secret Scanning API and webhook alert payloads."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_github_secret_scanning_report(report_data: Union[str, Dict[str, Any], Path, List[Dict[str, Any]]]) -> List[Finding]:
    """Parse GitHub Secret Scanning alert JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict/list, or Path to JSON file.

    Returns:
        List of normalized Finding models representing leaked secrets.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    alerts = data if isinstance(data, list) else data.get("alerts", [data])
    findings: List[Finding] = []

    for alert in alerts:
        secret_type = alert.get("secret_type", "github_token")
        type_name = alert.get("secret_type_display_name", secret_type.replace("_", " ").title())
        alert_number = str(alert.get("number", alert.get("id", "001")))
        
        # Location information
        location = alert.get("location", {})
        file_path = location.get("path", alert.get("path", "config.py"))
        line_num = int(location.get("start_line", alert.get("start_line", 1)))
        
        finding = Finding(
            id=f"gh-secret-{alert_number}",
            scanner="github-secret-scanning",
            finding_type=FindingType.SECRET,
            rule_id=f"github.secrets.{secret_type}",
            title=f"Exposed Secret: {type_name}",
            description=f"GitHub Secret Scanning identified active credential of type {type_name}.",
            severity=SeverityLevel.CRITICAL,
            cvss_score=9.5,
            cwe_ids=["CWE-798"],
            file_path=file_path,
            start_line=line_num,
            end_line=line_num,
            vulnerable_code=f"// Leaked {type_name} credential identified at line {line_num}"
        )
        findings.append(finding)

    return findings
