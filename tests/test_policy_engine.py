"""Unit tests for RemediationPolicyEngine."""

from agent_engine.policy_engine import RemediationPolicy, RemediationPolicyEngine
from agent_engine.state import Finding, FindingType, SeverityLevel


def create_sample_finding(severity=SeverityLevel.HIGH, cvss=8.0, cwe=["CWE-89"], path="target_repo/app.py"):
    return Finding(
        id="sample-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="rule.sqli",
        title="SQL Injection",
        description="SQL injection in endpoint",
        severity=severity,
        cwe_ids=cwe,
        cvss_score=cvss,
        file_path=path,
        start_line=10,
        end_line=12,
        vulnerable_code="SELECT * FROM users"
    )


def test_policy_allow_default():
    engine = RemediationPolicyEngine()
    finding = create_sample_finding()
    result = engine.evaluate_finding(finding)
    assert result.is_allowed is True
    assert result.action == "ALLOW"


def test_policy_block_low_cvss():
    policy = RemediationPolicy({"min_cvss": 7.0})
    engine = RemediationPolicyEngine(policy)

    finding = create_sample_finding(cvss=5.5)
    result = engine.evaluate_finding(finding)
    assert result.is_allowed is False
    assert result.action == "BLOCK"
    assert any("below minimum threshold" in r for r in result.reasons)


def test_policy_block_ignored_path():
    policy = RemediationPolicy({"ignored_path_patterns": ["vendor/"]})
    engine = RemediationPolicyEngine(policy)

    finding = create_sample_finding(path="vendor/third_party/lib.py")
    result = engine.evaluate_finding(finding)
    assert result.is_allowed is False
    assert any("matches ignored pattern" in r for r in result.reasons)


def test_policy_banned_cwe():
    policy = RemediationPolicy({"banned_cwes": ["CWE-78"]})
    engine = RemediationPolicyEngine(policy)

    finding = create_sample_finding(cwe=["CWE-78"])
    result = engine.evaluate_finding(finding)
    assert result.is_allowed is False
    assert any("banned" in r for r in result.reasons)
