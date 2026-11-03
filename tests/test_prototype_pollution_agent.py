from agent_engine.agents.prototype_pollution_agent import PrototypePollutionRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_prototype_pollution_remediation():
    finding = Finding(
        id="snyk-cwe-1321-merge",
        scanner="snyk",
        finding_type=FindingType.SAST,
        rule_id="CWE-1321",
        title="Improperly Controlled Modification of Object Attributes",
        description="Recursive merge allows __proto__ and __class__ pollution",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-1321"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = PrototypePollutionRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "DANGEROUS_KEYS" in updated.patch_diff
    assert "CWE-1321" in updated.patch_explanation
