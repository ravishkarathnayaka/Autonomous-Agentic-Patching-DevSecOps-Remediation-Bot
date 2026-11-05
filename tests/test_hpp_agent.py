from agent_engine.agents.hpp_agent import HppRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_hpp_agent_remediation():
    finding = Finding(
        id="acunetix-hpp-01",
        scanner="acunetix",
        finding_type=FindingType.DAST,
        rule_id="CWE-235",
        title="HTTP Parameter Pollution",
        description="Application does not sanitize duplicate query parameters on fund transfer",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-235"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = HppRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "getlist('recipient')" in updated.patch_diff
    assert "HTTP Parameter Pollution detected" in updated.patch_diff
    assert "CWE-235" in updated.patch_explanation
