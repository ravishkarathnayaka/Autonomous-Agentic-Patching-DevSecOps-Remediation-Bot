from agent_engine.agents.regex_timeout_agent import RegexTimeoutAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_regex_timeout_agent_remediation():
    finding = Finding(
        id="sonarcloud-redos-01",
        scanner="sonarcloud",
        finding_type=FindingType.SAST,
        rule_id="CWE-1333",
        title="Catastrophic Backtracking in Pattern Matching",
        description="Regular expression with nested repetition operators is vulnerable to ReDoS",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-1333"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = RegexTimeoutAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "RegexComplexityAuditor" in updated.patch_diff
    assert "Input length exceeds" in updated.patch_diff
    assert "CWE-1333" in updated.patch_explanation
