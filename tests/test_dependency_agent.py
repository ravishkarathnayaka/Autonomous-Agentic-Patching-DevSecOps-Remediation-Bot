from agent_engine.agents.dependency_agent import DependencyAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_dependency_agent_successful_upgrade():
    finding = Finding(
        id="sca-flask-1",
        scanner="trivy",
        finding_type=FindingType.SCA,
        rule_id="CVE-2023-30861",
        title="Flask Cookie Hijacking",
        description="Session disclosure",
        severity=SeverityLevel.HIGH,
        package_name="Flask",
        installed_version="2.2.0",
        fixed_version="2.2.5",
        file_path="target_repo/requirements.txt"
    )

    state = RemediationState(finding=finding, target_repo_path="target_repo")
    agent = DependencyAgent()
    updated_state = agent.execute(state)

    assert updated_state.status == RemediationStatus.PATCH_GENERATED
    assert updated_state.patch_diff is not None
    assert "-Flask==2.2.0" in updated_state.patch_diff
    assert "+Flask==2.2.5" in updated_state.patch_diff
    assert "CVE-2023-30861" in updated_state.patch_explanation


def test_dependency_agent_missing_fixed_version():
    finding = Finding(
        id="sca-no-fix",
        scanner="trivy",
        finding_type=FindingType.SCA,
        rule_id="CVE-9999",
        title="Unknown vuln",
        description="No fix available",
        severity=SeverityLevel.MEDIUM,
        package_name="vulnerable-lib",
        installed_version="1.0.0",
        fixed_version=None,
        file_path="requirements.txt"
    )

    state = RemediationState(finding=finding, target_repo_path="target_repo")
    agent = DependencyAgent()
    updated_state = agent.execute(state)

    assert updated_state.status == RemediationStatus.FAILED
