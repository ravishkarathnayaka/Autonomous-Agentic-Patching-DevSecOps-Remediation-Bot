from agent_engine.agents.randomness_agent import RandomnessHardeningAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_randomness_hardening_remediation():
    finding = Finding(
        id="bandit-b311-random",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="CWE-338",
        title="Use of Cryptographically Insecure Pseudo-Random Number Generator",
        description="Standard pseudo-random generators are not cryptographically secure",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-338", "CWE-330"],
        file_path="target_repo/session_mgr.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = RandomnessHardeningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "secrets.token_urlsafe" in updated.patch_diff
    assert "CWE-338" in updated.patch_explanation
