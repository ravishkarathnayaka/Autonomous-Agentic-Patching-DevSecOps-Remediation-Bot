from agent_engine.agents.cors_agent import CORSHardeningAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_cors_hardening():
    finding = Finding(
        id="zap-cors-wildcard",
        scanner="zap",
        finding_type=FindingType.DAST,
        rule_id="CWE-942",
        title="Permissive Cross-Origin Resource Sharing with credentials",
        description="Access-Control-Allow-Origin: * coupled with credentials: true",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-942"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = CORSHardeningAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "ALLOWED_ORIGINS" in updated.patch_diff
    assert "resp.headers['Vary'] = 'Origin'" in updated.patch_diff
    assert "wildcard reflection" in updated.patch_explanation
