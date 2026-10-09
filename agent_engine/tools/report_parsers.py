"""Parsers for normalizing Semgrep (SAST) and Trivy (SCA) scan reports into Finding models."""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
import uuid

from agent_engine.state import Finding, FindingType, SeverityLevel


def _map_semgrep_severity(raw_severity: str) -> SeverityLevel:
    """Map Semgrep severity (ERROR, WARNING, INFO) to standardized SeverityLevel."""
    normalized = (raw_severity or "").upper().strip()
    if normalized in ("ERROR", "CRITICAL"):
        return SeverityLevel.HIGH
    if normalized in ("WARNING", "WARN"):
        return SeverityLevel.MEDIUM
    if normalized in ("INFO", "EXPERIMENT"):
        return SeverityLevel.LOW
    return SeverityLevel.MEDIUM


def _map_trivy_severity(raw_severity: str) -> SeverityLevel:
    """Map Trivy severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN) to SeverityLevel."""
    normalized = (raw_severity or "").upper().strip()
    if normalized == "CRITICAL":
        return SeverityLevel.CRITICAL
    if normalized == "HIGH":
        return SeverityLevel.HIGH
    if normalized == "MEDIUM":
        return SeverityLevel.MEDIUM
    if normalized == "LOW":
        return SeverityLevel.LOW
    return SeverityLevel.INFO


def _extract_cwe_ids(raw_cwe: Any) -> List[str]:
    """Extract standard CWE identifiers (e.g. ['CWE-89']) from various scanner formats."""
    results: List[str] = []
    if isinstance(raw_cwe, str):
        candidates = [raw_cwe]
    elif isinstance(raw_cwe, list):
        candidates = [str(item) for item in raw_cwe]
    else:
        return results

    for item in candidates:
        import re
        match = re.search(r"CWE-(\d+)", item, re.IGNORECASE)
        if match:
            cwe_clean = f"CWE-{match.group(1)}"
            if cwe_clean not in results:
                results.append(cwe_clean)
        elif item.strip():
            results.append(item.strip())
    return results


def parse_semgrep_json(data: Dict[str, Any]) -> List[Finding]:
    """Parse Semgrep JSON output dictionary into a list of normalized Finding objects."""
    findings: List[Finding] = []
    raw_results = data.get("results", [])

    for item in raw_results:
        check_id = item.get("check_id", "unknown-semgrep-rule")
        path = item.get("path", "")
        start_line = item.get("start", {}).get("line", 1)
        end_line = item.get("end", {}).get("line", start_line)
        extra = item.get("extra", {})

        message = extra.get("message", "Semgrep security finding detected.")
        severity_str = extra.get("severity", "WARNING")
        severity = _map_semgrep_severity(severity_str)

        metadata = extra.get("metadata", {})
        raw_cwe = metadata.get("cwe", [])
        cwe_ids = _extract_cwe_ids(raw_cwe)

        cvss_score: Optional[float] = None
        if "cvss" in metadata:
            try:
                cvss_score = float(metadata["cvss"])
            except (ValueError, TypeError):
                pass

        lines = extra.get("lines", "")
        finding_id = f"semgrep-{check_id.split('.')[-1]}-{uuid.uuid4().hex[:8]}"

        finding = Finding(
            id=finding_id,
            scanner="semgrep",
            finding_type=FindingType.SAST,
            rule_id=check_id,
            title=f"Security issue: {check_id.split('.')[-1]}",
            description=message,
            severity=severity,
            cwe_ids=cwe_ids,
            cvss_score=cvss_score,
            file_path=path,
            start_line=start_line,
            end_line=end_line,
            vulnerable_code=lines,
            references=metadata.get("references", [])
        )
        findings.append(finding)

    return findings


def parse_trivy_json(data: Dict[str, Any]) -> List[Finding]:
    """Parse Trivy SCA JSON report into a list of normalized Finding objects."""
    findings: List[Finding] = []
    results_list = data.get("Results", [])

    for target_block in results_list:
        target_file = target_block.get("Target", "requirements.txt")
        vulns = target_block.get("Vulnerabilities", [])

        for vuln in vulns:
            vuln_id = vuln.get("VulnerabilityID", "CVE-UNKNOWN")
            pkg_name = vuln.get("PkgName", "unknown-pkg")
            installed_ver = vuln.get("InstalledVersion", "0.0.0")
            fixed_ver = vuln.get("FixedVersion")
            title = vuln.get("Title", f"Vulnerable dependency: {pkg_name} ({vuln_id})")
            description = vuln.get("Description", f"Dependency {pkg_name} contains vulnerability {vuln_id}.")
            severity = _map_trivy_severity(vuln.get("Severity", "UNKNOWN"))

            cwe_ids = _extract_cwe_ids(vuln.get("CweIDs", []))

            # Extract CVSS if present
            cvss_score: Optional[float] = None
            cvss_block = vuln.get("CVSS", {})
            for vendor_key in ("nvd", "ghsa", "redhat"):
                if vendor_key in cvss_block:
                    score = cvss_block[vendor_key].get("V3Score")
                    if score is not None:
                        try:
                            cvss_score = float(score)
                            break
                        except (ValueError, TypeError):
                            pass

            primary_url = vuln.get("PrimaryURL")
            references = [primary_url] if primary_url else []

            finding_id = f"trivy-{vuln_id.lower()}-{uuid.uuid4().hex[:8]}"
            finding = Finding(
                id=finding_id,
                scanner="trivy",
                finding_type=FindingType.SCA,
                rule_id=vuln_id,
                title=title,
                description=description,
                severity=severity,
                cwe_ids=cwe_ids,
                cvss_score=cvss_score,
                file_path=target_file,
                start_line=1,
                end_line=1,
                vulnerable_code=f"{pkg_name}=={installed_ver}",
                package_name=pkg_name,
                installed_version=installed_ver,
                fixed_version=fixed_ver,
                references=references
            )
            findings.append(finding)

    return findings


def load_findings_from_file(file_path: Union[str, Path]) -> List[Finding]:
    """Auto-detect scanner format and parse report file into Finding objects."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Report file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Detect format
    if isinstance(data, dict):
        if "issues" in data and isinstance(data["issues"], list):
            from agent_engine.tools.sonarqube_parser import parse_sonarqube_report
            return parse_sonarqube_report(data)
        if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            from agent_engine.tools.snyk_parser import parse_snyk_report
            return parse_snyk_report(data)
        if "check_type" in data or "passed_checks" in data:
            from agent_engine.tools.checkov_parser import parse_checkov_report
            return parse_checkov_report(data)
        if "dependencies" in data and isinstance(data["dependencies"], list):
            from agent_engine.tools.pip_audit_parser import parse_pip_audit_report
            return parse_pip_audit_report(data)
        if "metrics" in data and "results" in data:
            from agent_engine.tools.bandit_parser import parse_bandit_json
            return parse_bandit_json(data)
        if "results" in data and isinstance(data["results"], list):
            return parse_semgrep_json(data)
        if "Results" in data or "SchemaVersion" in data:
            return parse_trivy_json(data)

    elif isinstance(data, list):
        if data and isinstance(data[0], dict):
            if "Secret" in data[0] or "RuleID" in data[0]:
                from agent_engine.tools.gitleaks_parser import parse_gitleaks_report
                return parse_gitleaks_report(data)
            if "vulnerabilities" in data[0]:
                from agent_engine.tools.snyk_parser import parse_snyk_report
                return parse_snyk_report(data)
            if "check_id" in data[0]:
                return parse_semgrep_json({"results": data})
            if "VulnerabilityID" in data[0]:
                return parse_trivy_json({"Results": [{"Target": "dependencies", "Vulnerabilities": data}]})

    raise ValueError(f"Unsupported report format in {file_path}. Expected Semgrep, Trivy, Snyk, SonarQube, Gitleaks, Pip-Audit, Checkov, or Bandit JSON.")
