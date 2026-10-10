import pytest
from agent_engine.state import Finding, RemediationState, RemediationStatus, SeverityLevel, VerificationResult
from agent_engine.tools.explainer import RemediationExplainer


def test_explainer_format_rationale():
    finding = Finding(
        id="f100",
        scanner="semgrep",
        rule_id="python.sqli",
        title="SQL Injection in search",
        description="Dynamic string formatting allows SQL injection.",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        cvss_score=8.8,
        file_path="app.py",
        start_line=25,
        end_line=26
    )
    v_res = VerificationResult(
        passed=True,
        functional_tests_passed=True,
        security_tests_passed=True,
        syntax_valid=True,
        duration_seconds=1.45
    )
    state = RemediationState(
        finding=finding,
        target_repo_path="./target_repo",
        status=RemediationStatus.VERIFIED,
        patch_explanation="Converted query to parameterized statements.",
        verification_results=[v_res],
        commit_sha="a1b2c3d4"
    )

    markdown = RemediationExplainer.format_rationale_markdown(state)
    assert "Security Remediation Rationale" in markdown
    assert "CWE-89" in markdown
    assert "CVSS: 8.8" in markdown
    assert "Regression Unit Tests" in markdown
    assert "PASSED" in markdown
    assert "Security Re-scan" in markdown
    assert "CLEAN" in markdown
    assert "git revert a1b2c3d4" in markdown
