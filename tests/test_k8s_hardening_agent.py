from agent_engine.agents.k8s_hardening_agent import KubernetesHardeningAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_k8s_hardening_security_context():
    finding = Finding(
        id="kubescape-c-0016",
        scanner="kubescape",
        finding_type=FindingType.IAC,
        rule_id="C-0016",
        title="Privileged container detected",
        description="Container runs with elevated host capabilities",
        severity=SeverityLevel.HIGH,
        file_path="deploy/k8s.yaml"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = KubernetesHardeningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "allowPrivilegeEscalation: false" in updated.patch_diff
    assert "runAsNonRoot: true" in updated.patch_diff
    assert "drop:" in updated.patch_diff
    assert "Kubernetes Hardening" in updated.patch_explanation


def test_k8s_hardening_hostpath():
    finding = Finding(
        id="kubescape-c-0046",
        scanner="kubescape",
        finding_type=FindingType.IAC,
        rule_id="C-0046",
        title="HostPath volume mount",
        description="Mounts dangerous host socket",
        severity=SeverityLevel.CRITICAL,
        file_path="deploy/k8s.yaml"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = KubernetesHardeningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "emptyDir: {}" in updated.patch_diff
    assert "-        hostPath:" in updated.patch_diff
