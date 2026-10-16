from agent_engine.agents.dockerfile_agent import DockerfileAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_dockerfile_agent_apt_cleanup():
    finding = Finding(
        id="hadolint-dl3008",
        scanner="hadolint",
        finding_type=FindingType.IAC,
        rule_id="DL3008",
        title="Pin versions in apt get install",
        description="Avoid unpinned packages",
        severity=SeverityLevel.MEDIUM,
        file_path="docker/sandbox.Dockerfile"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = DockerfileAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "--no-install-recommends" in updated.patch_diff
    assert "rm -rf /var/lib/apt/lists/*" in updated.patch_diff
    assert "DL3008" in updated.patch_explanation
