from agent_engine.agents.cache_poisoning_agent import CachePoisoningAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_cache_poisoning_agent_remediation():
    finding = Finding(
        id="qualys-cache-01",
        scanner="qualys-was",
        finding_type=FindingType.DAST,
        rule_id="CWE-444",
        title="Web Cache Poisoning via Unkeyed Header",
        description="Response is cached with reflected host header allowing cache poisoning attacks",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-444", "CWE-524"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = CachePoisoningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "Cache-Control" in updated.patch_diff
    assert "no-store, no-cache" in updated.patch_diff
    assert "Vary" in updated.patch_diff
    assert "CWE-444" in updated.patch_explanation
