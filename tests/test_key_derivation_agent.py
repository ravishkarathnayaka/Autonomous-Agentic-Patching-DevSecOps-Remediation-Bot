from agent_engine.agents.key_derivation_agent import KeyDerivationHardeningAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_key_derivation_remediation():
    finding = Finding(
        id="bandit-cwe-916-pbkdf2",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="CWE-916",
        title="Use of Password Hash With Insufficient Computational Effort",
        description="Low PBKDF2 iteration count and static salt detected",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-916", "CWE-326"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = KeyDerivationHardeningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "600000" in updated.patch_diff
    assert "os.urandom(16)" in updated.patch_diff
    assert "CWE-916" in updated.patch_explanation
