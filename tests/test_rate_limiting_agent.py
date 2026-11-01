from agent_engine.agents.rate_limiting_agent import RateLimitingAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_rate_limiting_remediation():
    finding = Finding(
        id="semgrep-unbounded-allocation",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-770",
        title="Uncontrolled resource allocation in batch handler",
        description="Arbitrary length items list processed without limits",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-770"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = RateLimitingAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "MAX_BATCH_ITEMS = 100" in updated.patch_diff
    assert "413" in updated.patch_diff
    assert "CWE-770" in updated.patch_explanation
