from agent_engine.agents.log_injection_agent import LogInjectionSanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_log_injection_remediation():
    finding = Finding(
        id="bandit-cwe-117-log",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="CWE-117",
        title="Improper Output Handling for Logs",
        description="Unsanitized user parameters written to log stream",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-117"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = LogInjectionSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "clean_user" in updated.patch_diff
    assert "CWE-117" in updated.patch_explanation
