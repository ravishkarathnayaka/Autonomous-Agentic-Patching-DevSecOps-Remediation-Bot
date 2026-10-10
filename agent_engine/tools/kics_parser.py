"""Parser for normalizing Checkmarx KICS Infrastructure-as-Code (IaC) scan reports into Finding models."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from agent_engine.state import Finding, FindingType, SeverityLevel


def _map_kics_severity(severity_str: str) -> SeverityLevel:
    """Map KICS severity (HIGH, MEDIUM, LOW, INFO) to standardized SeverityLevel."""
    s = (severity_str or "").strip().upper()
    if s == "HIGH":
        return SeverityLevel.HIGH
    if s == "MEDIUM":
        return SeverityLevel.MEDIUM
    if s == "LOW":
        return SeverityLevel.LOW
    if s in ("INFO", "TRACE"):
        return SeverityLevel.INFO
    return SeverityLevel.MEDIUM


def parse_kics_report(data: Dict[str, Any]) -> List[Finding]:
    """Parse KICS JSON output dictionary into normalized Finding objects."""
    findings: List[Finding] = []
    queries = data.get("queries", [])

    for query in queries:
        query_name = query.get("query_name", "KICS IaC Misconfiguration")
        query_id = query.get("query_id", "kics-query")
        severity_str = query.get("severity", "MEDIUM")
        severity = _map_kics_severity(severity_str)
        category = query.get("category", "IaC Security")
        description = query.get("description", f"IaC misconfiguration detected: {query_name}")
        platform = query.get("platform", "Terraform")

        cwe_raw = query.get("cwe", "")
        cwe_ids: List[str] = []
        if cwe_raw:
            cwe_clean = f"CWE-{cwe_raw}" if not str(cwe_raw).upper().startswith("CWE-") else str(cwe_raw)
            cwe_ids.append(cwe_clean)

        files = query.get("files", [])
        for file_item in files:
            file_name = file_item.get("file_name", "main.tf")
            line = file_item.get("line", 1)
            search_key = file_item.get("search_key", "")
            issue_type = file_item.get("issue_type", "")
            key_actual_value = file_item.get("key_actual_value", "")

            finding_id = f"kics-{query_id[:8]}-{uuid.uuid4().hex[:8]}"

            vulnerable_snippet = f"Search Key: {search_key}\nIssue Type: {issue_type}\nDetail: {key_actual_value}"

            finding = Finding(
                id=finding_id,
                scanner="kics",
                finding_type=FindingType.IAC,
                rule_id=query_id,
                title=f"[{platform}] {query_name}",
                description=f"{description} (Category: {category})",
                severity=severity,
                cwe_ids=cwe_ids,
                file_path=file_name,
                start_line=line,
                end_line=line,
                vulnerable_code=vulnerable_snippet,
                references=[f"https://docs.kics.io/latest/queries/{platform.lower()}-queries/"]
            )
            findings.append(finding)

    return findings
