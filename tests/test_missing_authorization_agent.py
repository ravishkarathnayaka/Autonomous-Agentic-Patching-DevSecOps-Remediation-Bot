from agent_engine.agents.missing_authorization_agent import MissingAuthorizationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_missing_authorization_remediation():
    finding = Finding(
        id="semgrep-client-side-auth",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-602",
        title="Client-Side Security Check without Server Authorization",
        description="Endpoint relies on header flag for admin privilege validation",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-602", "CWE-862"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = MissingAuthorizationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "Authorization" in updated.patch_diff
    assert "Bearer" in updated.patch_diff
    assert "CWE-602" in updated.patch_explanation
