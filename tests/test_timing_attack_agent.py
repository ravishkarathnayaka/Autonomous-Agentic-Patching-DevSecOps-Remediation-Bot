from agent_engine.agents.timing_attack_agent import TimingAttackRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_timing_attack_remediation():
    finding = Finding(
        id="bandit-b105-timing",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="CWE-208",
        title="Observable Timing Discrepancy",
        description="Naive equality check on API secret token",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-208", "CWE-385"],
        file_path="target_repo/auth.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = TimingAttackRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "hmac.compare_digest" in updated.patch_diff
    assert "CWE-208" in updated.patch_explanation
