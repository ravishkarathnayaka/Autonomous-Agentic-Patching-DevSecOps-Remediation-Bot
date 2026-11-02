from agent_engine.agents.temp_file_agent import TempFileHardeningAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_temp_file_hardening_remediation():
    finding = Finding(
        id="bandit-b108-insecure-tmp",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="CWE-377",
        title="Insecure temporary file creation",
        description="Predictable temporary file path vulnerable to symlink race condition",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-377"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = TempFileHardeningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "NamedTemporaryFile" in updated.patch_diff
    assert "CWE-377" in updated.patch_explanation
