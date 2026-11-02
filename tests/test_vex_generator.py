import pytest
from agent_engine.state import Finding, FindingType, RemediationStatus, SeverityLevel
from agent_engine.tools.vex_generator import VexDocumentGenerator


def test_vex_document_generator_success():
    finding1 = Finding(
        id="cve-2023-1001",
        scanner="trivy",
        finding_type=FindingType.SCA,
        rule_id="CVE-2023-1001",
        title="Vulnerable requests dependency",
        description="Leaked credentials during HTTP redirect",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-200"],
        file_path="requirements.txt",
    )
    finding2 = Finding(
        id="cve-2023-2002",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-89",
        title="SQL Injection vulnerability",
        description="Unparameterized SQL string concat",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-89"],
        file_path="app/db.py",
    )

    statuses = {
        "cve-2023-1001": RemediationStatus.VERIFIED,
        "cve-2023-2002": RemediationStatus.INITIALIZED,
    }

    doc = VexDocumentGenerator.generate_openvex(
        document_id="https://example.com/vex/doc-001",
        author="DevSecOps-Bot",
        findings=[finding1, finding2],
        remediation_statuses=statuses,
    )

    assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert doc["author"] == "DevSecOps-Bot"
    assert len(doc["statements"]) == 2

    s1 = doc["statements"][0]
    assert s1["vulnerability"]["name"] == "CVE-2023-1001"
    assert s1["status"] == "fixed"

    s2 = doc["statements"][1]
    assert s2["vulnerability"]["name"] == "CWE-89"
    assert s2["status"] == "affected"
