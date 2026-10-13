"""Parser for GitHub CodeQL SARIF (Static Analysis Results Interchange Format) reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)

CODEQL_LEVEL_MAP = {
    "error": SeverityLevel.HIGH,
    "warning": SeverityLevel.MEDIUM,
    "note": SeverityLevel.LOW,
    "none": SeverityLevel.INFO,
}


def parse_codeql_sarif(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse GitHub CodeQL SARIF report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to SARIF file.

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
    runs = data.get("runs", []) if isinstance(data, dict) else []

    for run in runs:
        tool = run.get("tool", {}).get("driver", {})
        tool_name = tool.get("name", "CodeQL")
        rules_list = tool.get("rules", [])
        rules_map = {r.get("id"): r for r in rules_list if "id" in r}

        results = run.get("results", [])
        for res in results:
            try:
                rule_id = res.get("ruleId", "codeql-query")
                message = res.get("message", {}).get("text", "CodeQL Security Alert")
                raw_level = str(res.get("level", "warning")).lower()
                severity = CODEQL_LEVEL_MAP.get(raw_level, SeverityLevel.MEDIUM)

                rule_meta = rules_map.get(rule_id, {})
                properties = rule_meta.get("properties", {})
                tags = properties.get("tags", [])

                # Extract CWE IDs from tags or properties
                cwe_ids: List[str] = []
                for tag in tags:
                    if "cwe/cwe-" in tag.lower():
                        cwe_ids.append(tag.split("/")[-1].upper())

                cvss = properties.get("security-severity")
                cvss_score = float(cvss) if cvss is not None else None
                if cvss_score and cvss_score >= 9.0:
                    severity = SeverityLevel.CRITICAL
                elif cvss_score and cvss_score >= 7.0:
                    severity = SeverityLevel.HIGH

                locations = res.get("locations", [])
                file_path = "target_repo/app.py"
                start_line = 1
                end_line = 1
                snippet = ""

                if locations:
                    phys_loc = locations[0].get("physicalLocation", {})
                    artifact_loc = phys_loc.get("artifactLocation", {})
                    file_path = artifact_loc.get("uri", file_path)
                    region = phys_loc.get("region", {})
                    start_line = region.get("startLine", 1)
                    end_line = region.get("endLine", start_line)
                    snippet = region.get("snippet", {}).get("text", "")

                finding = Finding(
                    id=f"codeql-{rule_id}-{start_line}",
                    scanner="codeql",
                    finding_type=FindingType.SAST,
                    rule_id=rule_id,
                    title=f"CodeQL: {rule_meta.get('shortDescription', {}).get('text', message)}",
                    description=message,
                    severity=severity,
                    cwe_ids=cwe_ids or ["CWE-20"],
                    cvss_score=cvss_score,
                    file_path=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    vulnerable_code=snippet or f"# Flagged by {tool_name} at line {start_line}",
                    references=[rule_meta.get("helpUri")] if rule_meta.get("helpUri") else []
                )
                findings.append(finding)
            except Exception as e:
                logger.warning("Failed to parse CodeQL result: %s", e)
                continue

    logger.info("Successfully parsed %d findings from CodeQL SARIF report.", len(findings))
    return findings
