from agent_engine.agents.ssrf_agent import SSRFRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_ssrf_remediation():
    finding = Finding(
        id="semgrep-ssrf-requests",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="python.requests.security.ssrf",
        title="Server-Side Request Forgery via untrusted URL",
        description="Arbitrary network egress to internal infrastructure",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-918"],
        file_path="services/fetcher.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = SSRFRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "target_ip.is_private" in updated.patch_diff
    assert "169.254.169.254" in updated.patch_explanation
    assert "SSRF blocked" in updated.patch_diff
