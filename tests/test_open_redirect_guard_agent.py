from agent_engine.agents.open_redirect_guard_agent import OpenRedirectGuardAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_open_redirect_guard_agent_remediation():
    finding = Finding(
        id="acunetix-open-redirect-01",
        scanner="acunetix",
        finding_type=FindingType.DAST,
        rule_id="CWE-601",
        title="URL Redirection to Untrusted Site",
        description="Redirecting client to unvalidated external location enables credential phishing",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-601"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = OpenRedirectGuardAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "OpenRedirectValidator" in updated.patch_diff
    assert "is_safe_redirect" in updated.patch_diff
    assert "CWE-601" in updated.patch_explanation
