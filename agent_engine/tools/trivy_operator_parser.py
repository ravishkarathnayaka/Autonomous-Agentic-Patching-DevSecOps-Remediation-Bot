"""Parser for Aqua Security Trivy Operator Kubernetes CRD vulnerability reports."""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Union

from agent_engine.state import Finding, FindingType, SeverityLevel

logger = logging.getLogger(__name__)


def parse_trivy_operator_report(report_data: Union[str, Dict[str, Any], Path]) -> List[Finding]:
    """Parse Trivy Operator VulnerabilityReport CRD JSON into normalized Finding models.

    Args:
        report_data: Raw JSON string, parsed dict, or Path to JSON file.

    Returns:
        List of normalized Finding models representing Kubernetes container vulnerabilities.
    """
    if isinstance(report_data, Path):
        data = json.loads(report_data.read_text(encoding="utf-8"))
    elif isinstance(report_data, str):
        data = json.loads(report_data)
    else:
        data = report_data

    findings: List[Finding] = []
    metadata = data.get("metadata", {})
    pod_name = metadata.get("name", "k8s-pod")
    namespace = metadata.get("namespace", "default")
    
    report = data.get("report", {})
    vulns = report.get("vulnerabilities", [])

    for v in vulns:
        vuln_id = v.get("vulnerabilityID", "CVE-UNKNOWN")
        pkg_name = v.get("pkgName", "unknown-package")
        installed_ver = v.get("installedVersion", "0.0.0")
        fixed_ver = v.get("fixedVersion", "")
        title = v.get("title", f"Kubernetes Workload CVE: {vuln_id}")
        score = float(v.get("score", 5.0)) if v.get("score") is not None else 5.0
        sev_raw = str(v.get("severity", "MEDIUM")).upper()

        if sev_raw == "CRITICAL":
            severity = SeverityLevel.CRITICAL
        elif sev_raw == "HIGH":
            severity = SeverityLevel.HIGH
        elif sev_raw == "LOW":
            severity = SeverityLevel.LOW
        else:
            severity = SeverityLevel.MEDIUM

        finding = Finding(
            id=f"trivy-op-{vuln_id.lower()}-{pkg_name}",
            scanner="trivy-operator",
            finding_type=FindingType.CONTAINER,
            rule_id=vuln_id,
            title=f"K8s Container Vulnerability: {pkg_name} ({vuln_id})",
            description=f"Cluster namespace {namespace}, workload {pod_name}: {title}",
            severity=severity,
            cvss_score=score,
            cwe_ids=["CWE-1395"],
            file_path=f"k8s/{namespace}/{pod_name}.yaml",
            start_line=1,
            end_line=1,
            vulnerable_code=f"image component: {pkg_name}=={installed_ver} -> upgrade to {fixed_ver or 'latest'}"
        )
        findings.append(finding)

    return findings
