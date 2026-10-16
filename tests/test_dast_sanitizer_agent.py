from agent_engine.agents.dast_sanitizer_agent import DASTSanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_dast_sanitizer_agent_csp():
    finding = Finding(
        id="dast-csp",
        scanner="owasp_zap",
        finding_type=FindingType.SAST,
        rule_id="ZAP-10038",
        title="Missing CSP Header",
        description="CSP header not present",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-693"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path="target_repo")
    agent = DASTSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "Content-Security-Policy" in updated.patch_diff
    assert "Strict-Transport-Security" in updated.patch_diff
    assert "X-Frame-Options" in updated.patch_diff
    assert "OWASP Top 10" in updated.patch_explanation
