from agent_engine.agents.csp_agent import ContentSecurityPolicyAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_csp_agent_remediation():
    finding = Finding(
        id="zap-missing-csp-headers",
        scanner="zap",
        finding_type=FindingType.DAST,
        rule_id="CWE-693",
        title="Missing Content-Security-Policy and X-Frame-Options",
        description="Endpoint sensitive view returned without security headers",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-693"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = ContentSecurityPolicyAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "Content-Security-Policy" in updated.patch_diff
    assert "X-Frame-Options" in updated.patch_diff
    assert "X-Content-Type-Options" in updated.patch_diff
    assert "CWE-693" in updated.patch_explanation
