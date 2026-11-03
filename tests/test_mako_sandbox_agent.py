from agent_engine.agents.mako_sandbox_agent import MakoSandboxAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_mako_sandbox_remediation():
    finding = Finding(
        id="semgrep-cwe-1336-ssti",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-1336",
        title="Improper Neutralization in Template Engine",
        description="render_template_string used on unsanitized user payload",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-1336", "CWE-94"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = MakoSandboxAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "SandboxedEnvironment" in updated.patch_diff
    assert "CWE-1336" in updated.patch_explanation
