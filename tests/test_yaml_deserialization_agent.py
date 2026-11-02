from agent_engine.agents.yaml_deserialization_agent import YamlDeserializationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_yaml_deserialization_remediation():
    finding = Finding(
        id="bandit-b506-yaml-load",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="CWE-502",
        title="Use of unsafe yaml.load",
        description="yaml.load called without safe loader allows arbitrary code execution",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-502"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = YamlDeserializationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "yaml.safe_load(raw_yaml)" in updated.patch_diff
    assert "CWE-502" in updated.patch_explanation
