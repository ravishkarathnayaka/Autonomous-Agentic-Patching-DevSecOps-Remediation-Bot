from agent_engine.agents.session_hardening_agent import SessionHardeningAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_session_hardening_remediation():
    finding = Finding(
        id="semgrep-insecure-cookie",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-614",
        title="Sensitive cookie missing security flags",
        description="Cookie created without HttpOnly and Secure flags",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-614"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = SessionHardeningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "httponly=True" in updated.patch_diff
    assert "secure=True" in updated.patch_diff
    assert "samesite='Strict'" in updated.patch_diff
    assert "CWE-614" in updated.patch_explanation
