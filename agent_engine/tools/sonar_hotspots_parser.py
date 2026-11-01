"""Parser for SonarQube Security Hotspots reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_sonar_hotspots_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse SonarQube Security Hotspots report JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    hotspots = data.get("hotspots", [])

    for h in hotspots:
        key = h.get("key", "hotspot-001")
        component = h.get("component", "app.py").split(":")[-1]
        line = int(h.get("line", 1))
        message = h.get("message", "Review this code segment for security sensitivity.")
        prob = str(h.get("vulnerabilityProbability", "MEDIUM")).upper()
        category = h.get("securityCategory", "security-hotspot")

        if prob == "HIGH":
            severity = SeverityLevel.HIGH
            cvss = 7.0
        elif prob == "LOW":
            severity = SeverityLevel.LOW
            cvss = 3.5
        else:
            severity = SeverityLevel.MEDIUM
            cvss = 5.0

        cwe_map = {
            "sql-injection": "CWE-89",
            "command-injection": "CWE-78",
            "insecure-cookie": "CWE-614",
            "cors": "CWE-942",
            "weak-cryptography": "CWE-327"
        }
        cwe_id = cwe_map.get(category.lower(), "CWE-693")

        finding = Finding(
            id=f"sonar-hotspot-{key}",
            scanner="sonarqube-hotspots",
            finding_type=FindingType.SAST,
            rule_id=f"sonar.hotspot.{category}",
            title=f"SonarQube Hotspot: {category} ({prob} probability)",
            description=message,
            severity=severity,
            cvss_score=cvss,
            cwe_ids=[cwe_id],
            file_path=component,
            start_line=line,
            end_line=line,
            vulnerable_code=f"// Hotspot key: {key} ({category})"
        )
        findings.append(finding)

    return findings
