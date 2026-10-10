import pytest
from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.finding_aggregator import FindingAggregator


def test_finding_aggregator_deduplication():
    f1 = Finding(
        id="f1",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="python.lang.security.audit.sqli",
        title="SQL Injection",
        description="SQL injection in db query",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-89"],
        file_path="app.py",
        start_line=25,
        cvss_score=6.5
    )
    f2 = Finding(
        id="f2",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="B608",
        title="SQL Injection detected",
        description="Dynamic string formatting in execute",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        file_path="app.py",
        start_line=25,
        cvss_score=8.5,
        references=["https://cwe.mitre.org/data/definitions/89.html"]
    )
    f3 = Finding(
        id="f3",
        scanner="trivy",
        finding_type=FindingType.SCA,
        rule_id="CVE-2023-32681",
        title="Requests CVE",
        description="Vulnerable requests version",
        severity=SeverityLevel.CRITICAL,
        file_path="requirements.txt",
        package_name="requests"
    )

    agg = FindingAggregator()
    agg.add_findings([f1, f2, f3])
    merged = agg.deduplicate()

    # f1 and f2 should be merged into 1 finding, f3 is distinct
    assert len(merged) == 2

    # Should be sorted by severity descending: CRITICAL (f3) first, then HIGH (merged f1+f2)
    assert merged[0].severity == SeverityLevel.CRITICAL
    assert merged[0].package_name == "requests"

    assert merged[1].severity == SeverityLevel.HIGH  # elevated from MEDIUM by bandit
    assert "semgrep+bandit" in merged[1].scanner
    assert merged[1].cvss_score == 8.5
    assert "https://cwe.mitre.org/data/definitions/89.html" in merged[1].references
