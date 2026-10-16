"""Parser for OWASP ZAP DAST (Dynamic Application Security Testing) JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

ZAP_RISK_MAP = {
    "3": SeverityLevel.HIGH,
    "2": SeverityLevel.MEDIUM,
    "1": SeverityLevel.LOW,
    "0": SeverityLevel.INFO,
    "high": SeverityLevel.HIGH,
    "medium": SeverityLevel.MEDIUM,
    "low": SeverityLevel.LOW,
    "informational": SeverityLevel.INFO,
}


def parse_zap_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse OWASP ZAP JSON alert report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to ZAP report file.

    Returns:
        List of normalized Finding models for dynamic flaws.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    sites = data.get("site", []) if isinstance(data, dict) else []
    if isinstance(sites, dict):
        sites = [sites]

    findings: List[Finding] = []

    for site in sites:
        alerts = site.get("alerts", [])
        for alert in alerts:
            try:
                plugin_id = alert.get("pluginId", "zap-alert")
                alert_name = alert.get("alert", "DAST Security Finding")
                desc = alert.get("desc", alert_name)
                risk_code = str(alert.get("riskcode", alert.get("riskdesc", "2"))).lower().split()[0]
                severity = ZAP_RISK_MAP.get(risk_code, SeverityLevel.MEDIUM)
                cwe_id = alert.get("cweid")
                cwe_list = [f"CWE-{cwe_id}"] if cwe_id and str(cwe_id) != "0" else ["CWE-693"]

                instances = alert.get("instances", [])
                uri = instances[0].get("uri", "/") if instances else "/"
                param = instances[0].get("param", "") if instances else ""
                attack = instances[0].get("attack", "") if instances else ""

                finding = Finding(
                    id=f"zap-{plugin_id}-{hash(uri) % 10000}",
                    scanner="owasp_zap",
                    finding_type=FindingType.SAST,
                    rule_id=f"ZAP-{plugin_id}",
                    title=f"OWASP ZAP DAST: {alert_name}",
                    description=desc,
                    severity=severity,
                    cwe_ids=cwe_list,
                    cvss_score=7.5 if severity == SeverityLevel.HIGH else 5.0,
                    file_path="target_repo/app.py",
                    start_line=1,
                    end_line=1,
                    vulnerable_code=f"# Dynamic flaw on URI {uri} (param: '{param}', attack payload: '{attack}')",
                    references=[alert.get("reference")] if alert.get("reference") else []
                )
                findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse ZAP alert item: %s", e)
                continue

    logger.info("Successfully parsed %d findings from OWASP ZAP report.", len(findings))
    return findings
