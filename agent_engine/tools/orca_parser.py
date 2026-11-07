"""Parser for Orca Security cloud infrastructure & workload vulnerability alerts."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_orca_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Orca Security JSON report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing cloud vulnerability findings.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    alerts = data.get("data", []) if isinstance(data, dict) else []
    if not alerts and isinstance(data, dict):
        alerts = data.get("alerts", [])

    for idx, alert in enumerate(alerts, start=1):
        rule_id = alert.get("cve_id", alert.get("rule_id", f"ORCA-{idx}"))
        title = alert.get("summary", alert.get("title", "Orca Security Finding"))
        description = alert.get("description", title)
        asset_name = alert.get("asset_name", alert.get("resource_name", "cloud_vm"))
        score = float(alert.get("score", 5.0)) if "score" in alert else None
        sev_raw = str(alert.get("priority", alert.get("severity", "medium"))).upper()
        cwe = alert.get("cwe", "")

        if sev_raw in ["CRITICAL", "P1"] or (score and score >= 9.0):
            severity = SeverityLevel.CRITICAL
        elif sev_raw in ["HIGH", "P2"] or (score and score >= 7.0):
            severity = SeverityLevel.HIGH
        elif sev_raw in ["LOW", "P4", "INFO"]:
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        cwe_list = [cwe] if cwe and cwe.startswith("CWE-") else ["CWE-16"]

        findings.append(
            Finding(
                id=f"orca-{rule_id}-{idx}",
                scanner="orca",
                finding_type=FindingType.CLOUD,
                rule_id=rule_id,
                title=f"{title} on {asset_name}",
                description=description,
                severity=severity,
                cwe_ids=cwe_list,
                cvss_score=score,
                file_path=str(asset_name),
                start_line=1,
                end_line=1,
                references=[f"https://app.orcasecurity.io/alerts/{rule_id}"],
            )
        )

    return findings
