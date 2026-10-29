"""Parser for Kubescape Kubernetes security scanner JSON reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_kubescape_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Kubescape JSON scan report into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to report file.

    Returns:
        List of normalized Finding models representing Kubernetes misconfigurations.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []

    # Handle Kubescape results structure
    results = data.get("results", [])
    if not results and "controls" in data:
        results = data.get("controls", [])

    for item in results:
        control_id = item.get("controlID", item.get("id", "C-0001"))
        name = item.get("name", "Kubernetes Security Misconfiguration")
        description = item.get("description", "")
        status = item.get("status", "failed")

        if str(status).lower() not in {"failed", "warning"}:
            continue

        base_score = float(item.get("baseScore", 6.5))
        if base_score >= 8.0:
            severity = SeverityLevel.CRITICAL
        elif base_score >= 6.0:
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.MEDIUM

        file_path = item.get("filePath", "deployments/k8s-deployment.yaml")
        line_number = int(item.get("lineNumber", 1) or 1)

        finding = Finding(
            id=f"kubescape-{control_id.lower()}-{line_number}",
            scanner="kubescape",
            finding_type=FindingType.IAC,
            rule_id=control_id,
            title=f"Kubescape Control {control_id}: {name}",
            description=description or name,
            severity=severity,
            cwe_ids=["CWE-250", "CWE-732"],
            cvss_score=base_score,
            file_path=file_path,
            start_line=line_number,
            end_line=line_number,
            vulnerable_code=item.get("highlightedCode", "securityContext:\n  privileged: true")
        )
        findings.append(finding)

    return findings
