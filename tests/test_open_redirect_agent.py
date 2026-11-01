from agent_engine.agents.open_redirect_agent import OpenRedirectAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_open_redirect_remediation():
    finding = Finding(
        id="semgrep-open-redirect",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-601",
        title="Open Redirect via unvalidated query param",
        description="Arbitrary external redirect allowed in handler",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-601"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = OpenRedirectAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "urlparse(target)" in updated.patch_diff
    assert "corp.internal" in updated.patch_diff
    assert "CWE-601" in updated.patch_explanation
