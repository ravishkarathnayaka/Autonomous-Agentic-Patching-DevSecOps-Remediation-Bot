"""Parser for KICS (Keeping Infrastructure as Code Secure) JSON scan reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

KICS_SEV_MAP = {
    "HIGH": SeverityLevel.HIGH,
    "MEDIUM": SeverityLevel.MEDIUM,
    "LOW": SeverityLevel.LOW,
    "INFO": SeverityLevel.INFO,
}


def parse_kics_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse KICS IaC scan JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to KICS output JSON.

    Returns:
        List of normalized Finding models for IaC issues.
    """
    if isinstance(report_data, Path):
        with open(report_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    queries = data.get("queries", []) if isinstance(data, dict) else []
    findings: List[Finding] = []

    for query in queries:
        query_id = query.get("query_id", "KICS-QUERY")
        query_name = query.get("query_name", "IaC Security Misconfiguration")
        raw_sev = str(query.get("severity", "MEDIUM")).upper()
        severity = KICS_SEV_MAP.get(raw_sev, SeverityLevel.MEDIUM)
        desc = query.get("description", query_name)
        cwe = query.get("cwe")
        cwe_ids = [f"CWE-{cwe}"] if cwe else ["CWE-16"]

        files = query.get("files", [])
        for file_info in files:
            try:
                file_name = file_info.get("file_name", "Dockerfile")
                line = file_info.get("line", 1)
                search_key = file_info.get("search_key", "")
                actual_val = file_info.get("actual_value", "")

                finding = Finding(
                    id=f"kics-{query_id}-{line}",
                    scanner="kics",
                    finding_type=FindingType.IAC,
                    rule_id=query_id,
                    title=f"KICS IaC: {query_name}",
                    description=desc,
                    severity=severity,
                    cwe_ids=cwe_ids,
                    cvss_score=8.0 if severity == SeverityLevel.HIGH else 5.5,
                    file_path=file_name,
                    start_line=line,
                    end_line=line,
                    vulnerable_code=f"# {search_key}: {actual_val}",
                    references=[query.get("platformUrl")] if query.get("platformUrl") else []
                )
                findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse KICS finding file item: %s", e)
                continue

    logger.info("Successfully parsed %d findings from KICS report.", len(findings))
    return findings
