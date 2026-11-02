from agent_engine.agents.xpath_sanitizer_agent import XPathSanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_xpath_sanitizer_remediation():
    finding = Finding(
        id="semgrep-xpath-injection",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-643",
        title="XPath Injection via string formatting",
        description="User input dynamically formatted into XPath expression",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-643"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = XPathSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "safe_username" in updated.patch_diff
    assert "CWE-643" in updated.patch_explanation
