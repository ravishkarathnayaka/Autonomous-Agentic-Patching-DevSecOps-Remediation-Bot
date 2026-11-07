from agent_engine.agents.pickle_deserialization_agent import PickleDeserializationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_pickle_deserialization_agent_remediation():
    finding = Finding(
        id="semgrep-pickle-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-502",
        title="Deserialization of Untrusted Data via Pickle",
        description="Unpickling untrusted network input enables arbitrary code execution",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-502"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = PickleDeserializationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "json.loads" in updated.patch_diff
    assert "Insecure deserialization prohibited" in updated.patch_diff
    assert "CWE-502" in updated.patch_explanation
