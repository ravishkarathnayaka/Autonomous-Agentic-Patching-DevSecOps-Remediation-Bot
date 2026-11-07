from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.defectdojo_formatter import DefectDojoFormatter


def test_defectdojo_formatter_critical():
    finding = Finding(
        id="semgrep-cwe89-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-89",
        title="SQL Injection in search",
        description="Raw string formatting in SQL query",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-89"],
        cvss_score=9.8,
        file_path="target_repo/app.py",
        start_line=15,
        vulnerable_code="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
    )

    payload = DefectDojoFormatter.format_finding(
        finding,
        test_id=42,
        is_verified=True,
        mitigation_summary="Query parameterized with tuple binding.",
        additional_tags=["sprint-24"],
    )

    assert payload["test"] == 42
    assert payload["severity"] == "Critical"
    assert payload["cwe"] == 89
    assert payload["cvssv3_score"] == "9.8"
    assert payload["verified"] is True
    assert "sprint-24" in payload["tags"]
    assert "semgrep" in payload["tags"]
    assert "Query parameterized" in payload["mitigation"]


def test_defectdojo_formatter_cve():
    finding = Finding(
        id="trivy-cve-01",
        scanner="trivy",
        finding_type=FindingType.SCA,
        rule_id="CVE-2023-38545",
        title="curl SOCKS5 buffer overflow",
        description="Heap buffer overflow in curl library",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-122"],
        file_path="requirements.txt",
    )

    payload = DefectDojoFormatter.format_finding(finding)
    assert payload["severity"] == "High"
    assert payload["cve"] == "CVE-2023-38545"
    assert payload["cwe"] == 122
