"""Parser for normalizing Horusec multi-language SAST scan reports into Finding models."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from agent_engine.state import Finding, FindingType, SeverityLevel


def _map_horusec_severity(raw_severity: str) -> SeverityLevel:
    """Map Horusec severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) to SeverityLevel."""
    s = (raw_severity or "").strip().upper()
    if s == "CRITICAL":
        return SeverityLevel.CRITICAL
    if s == "HIGH":
        return SeverityLevel.HIGH
    if s == "MEDIUM":
        return SeverityLevel.MEDIUM
    if s == "LOW":
        return SeverityLevel.LOW
    if s in ("INFO", "AUDIT"):
        return SeverityLevel.INFO
    return SeverityLevel.MEDIUM


def parse_horusec_report(data: Dict[str, Any]) -> List[Finding]:
    """Parse Horusec JSON report into normalized Finding objects."""
    findings: List[Finding] = []
    items = data.get("analysisVulnerabilities", [])

    for item in items:
        vuln = item.get("vulnerabilities", {})
        rule_id = vuln.get("rule_id", "HS-SAST-VULN")
        severity_str = vuln.get("severity", "MEDIUM")
        severity = _map_horusec_severity(severity_str)
        details = vuln.get("details", f"Horusec SAST issue {rule_id}")
        file_path = vuln.get("file", "app.py")
        code = vuln.get("code", "")
        language = vuln.get("language", "Unknown")

        try:
            line = int(vuln.get("line", 1))
        except (ValueError, TypeError):
            line = 1

        cwe_ids: List[str] = []
        details_lower = details.lower()
        if "sql" in details_lower:
            cwe_ids.append("CWE-89")
        elif "command" in details_lower:
            cwe_ids.append("CWE-78")
        elif "xss" in details_lower or "cross site" in details_lower:
            cwe_ids.append("CWE-79")
        elif "path" in details_lower or "traversal" in details_lower:
            cwe_ids.append("CWE-22")

        finding_id = f"horusec-{rule_id.lower()}-{uuid.uuid4().hex[:8]}"

        finding = Finding(
            id=finding_id,
            scanner="horusec",
            finding_type=FindingType.SAST,
            rule_id=rule_id,
            title=f"[{language}] {details[:60]}",
            description=details,
            severity=severity,
            cwe_ids=cwe_ids,
            file_path=file_path,
            start_line=line,
            end_line=line,
            vulnerable_code=code,
            references=["https://horusec.io/"]
        )
        findings.append(finding)

    return findings
