from agent_engine.agents.mass_assignment_guard_agent import MassAssignmentGuardAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_mass_assignment_guard_agent_remediation():
    finding = Finding(
        id="contrast-mass-assign-01",
        scanner="contrast",
        finding_type=FindingType.SAST,
        rule_id="CWE-915",
        title="Improperly Controlled Modification of Dynamically-Determined Object Attributes",
        description="Blind dictionary update allows altering is_admin privilege flag",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-915"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = MassAssignmentGuardAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "MassAssignmentAuditor" in updated.patch_diff
    assert "filter_allowed_fields" in updated.patch_diff
    assert "CWE-915" in updated.patch_explanation
