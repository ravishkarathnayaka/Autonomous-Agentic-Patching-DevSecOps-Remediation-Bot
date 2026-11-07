from agent_engine.agents.xpath_parameterization_agent import XpathParameterizationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_xpath_parameterization_agent_remediation():
    finding = Finding(
        id="bandit-xpath-01",
        scanner="bandit",
        finding_type=FindingType.SAST,
        rule_id="CWE-643",
        title="Improper Neutralization of Data within XPath Expressions",
        description="Dynamic string formatting into root.findall xpath query",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-643"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = XpathParameterizationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "XpathStructureValidator" in updated.patch_diff
    assert "is_safe_literal" in updated.patch_diff
    assert "CWE-643" in updated.patch_explanation
