from agent_engine.agents.iac_agent import IaCAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_iac_agent_dockerfile_user():
    finding = Finding(
        id="iac-docker-root",
        scanner="kics",
        finding_type=FindingType.IAC,
        rule_id="missing-user-instruction",
        title="Container running as root",
        description="Missing USER instruction in Dockerfile",
        severity=SeverityLevel.HIGH,
        file_path="docker/Dockerfile"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = IaCAgent()
    updated_state = agent.execute(state)

    assert updated_state.status == RemediationStatus.PATCH_GENERATED
    assert updated_state.patch_diff is not None
    assert "+USER appuser" in updated_state.patch_diff
    assert "least-privilege" in updated_state.patch_explanation


def test_iac_agent_k8s_privileged():
    finding = Finding(
        id="iac-k8s-priv",
        scanner="checkov",
        finding_type=FindingType.IAC,
        rule_id="CKV_K8S_16",
        title="Privileged container enabled",
        description="Container runs in privileged mode",
        severity=SeverityLevel.CRITICAL,
        file_path="k8s/deployment.yaml"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = IaCAgent()
    updated_state = agent.execute(state)

    assert updated_state.status == RemediationStatus.PATCH_GENERATED
    assert "+      privileged: false" in updated_state.patch_diff
    assert "+      readOnlyRootFilesystem: true" in updated_state.patch_diff
