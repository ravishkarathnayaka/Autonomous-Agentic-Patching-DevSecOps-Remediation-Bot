from agent_engine.agents.redos_agent import RegexDosRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_redos_remediation():
    finding = Finding(
        id="semgrep-python-redos",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="python.lang.security.audit.regex-dos",
        title="Regular Expression Denial of Service",
        description="Exponential backtracking in regex matching",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-1333"],
        file_path="utils/validator.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = RegexDosRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "len(user_text) > 256" in updated.patch_diff
    assert "^[a-zA-Z0-9]+$" in updated.patch_diff
    assert "catastrophic backtracking" in updated.patch_explanation
