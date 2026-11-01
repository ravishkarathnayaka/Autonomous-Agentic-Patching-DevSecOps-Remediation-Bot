from agent_engine.agents.mass_assignment_agent import MassAssignmentAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_mass_assignment_remediation():
    finding = Finding(
        id="semgrep-mass-assignment",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-915",
        title="Mass Assignment parameter tampering",
        description="Raw dictionary update allows arbitrary parameter overwriting",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-915"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = MassAssignmentAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "ALLOWED_FIELDS" in updated.patch_diff
    assert "filtered_data" in updated.patch_diff
    assert "CWE-915" in updated.patch_explanation
