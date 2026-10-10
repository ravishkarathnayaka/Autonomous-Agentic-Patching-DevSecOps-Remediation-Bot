"""Parser for normalizing OWASP ZAP (DAST) JSON reports into Finding models."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from agent_engine.state import Finding, FindingType, SeverityLevel


def _map_zap_riskcode(risk_code: Any, risk_desc: Optional[str] = None) -> SeverityLevel:
    """Map OWASP ZAP risk code (0=Informational, 1=Low, 2=Medium, 3=High) to SeverityLevel."""
    code_str = str(risk_code).strip()
    if code_str == "3":
        return SeverityLevel.HIGH
    if code_str == "2":
        return SeverityLevel.MEDIUM
    if code_str == "1":
        return SeverityLevel.LOW
    if code_str == "0":
        return SeverityLevel.INFO

    desc_lower = (risk_desc or "").lower()
    if "high" in desc_lower or "critical" in desc_lower:
        return SeverityLevel.HIGH
    if "medium" in desc_lower:
        return SeverityLevel.MEDIUM
    if "low" in desc_lower:
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def parse_zap_report(data: Dict[str, Any]) -> List[Finding]:
    """Parse OWASP ZAP JSON scan report into normalized Finding objects."""
    findings: List[Finding] = []

    # Handle top-level alerts list or site array
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    alerts_list: List[Dict[str, Any]] = []
    if sites:
        for site in sites:
            site_alerts = site.get("alerts", [])
            alerts_list.extend(site_alerts)
    elif "alerts" in data:
        alerts_list = data.get("alerts", [])

    for alert in alerts_list:
        plugin_id = str(alert.get("pluginId", alert.get("alertRef", "zap-alert")))
        title = alert.get("name", alert.get("alert", "OWASP ZAP Finding"))
        desc = alert.get("desc", alert.get("description", ""))
        # Strip simple HTML markup if present
        clean_desc = desc.replace("<p>", "").replace("</p>", "").strip()
        
        risk_code = alert.get("riskcode", "")
        risk_desc = alert.get("riskdesc", "")
        severity = _map_zap_riskcode(risk_code, risk_desc)

        cwe_raw = alert.get("cweid", "")
        cwe_ids: List[str] = []
        if cwe_raw and str(cwe_raw) != "-1" and str(cwe_raw) != "0":
            cwe_ids.append(f"CWE-{cwe_raw}")

        instances = alert.get("instances", [])
        uri = ""
        param = ""
        attack = ""
        if instances and isinstance(instances, list):
            first = instances[0]
            uri = first.get("uri", "")
            param = first.get("param", "")
            attack = first.get("attack", "")

        solution = alert.get("solution", "").replace("<p>", "").replace("</p>", "").strip()
        reference = alert.get("reference", "").replace("<p>", "").replace("</p>", "").strip()
        references = [r.strip() for r in reference.split("\n") if r.strip()]

        file_path = uri if uri else "api_endpoint"
        vulnerable_code = f"Parameter: {param} | Attack vector: {attack}" if attack else f"URI: {uri}"

        finding_id = f"zap-{plugin_id}-{uuid.uuid4().hex[:8]}"

        finding = Finding(
            id=finding_id,
            scanner="owasp_zap",
            finding_type=FindingType.DAST,
            rule_id=plugin_id,
            title=title,
            description=clean_desc or f"DAST alert: {title}. Recommendation: {solution}",
            severity=severity,
            cwe_ids=cwe_ids,
            file_path=file_path,
            start_line=1,
            end_line=1,
            vulnerable_code=vulnerable_code,
            references=references
        )
        findings.append(finding)

    return findings
