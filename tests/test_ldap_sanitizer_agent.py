from agent_engine.agents.ldap_sanitizer_agent import LdapSanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_ldap_sanitizer_remediation():
    finding = Finding(
        id="semgrep-ldap-injection",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-90",
        title="LDAP Query Injection",
        description="User input directly concatenated into directory query",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-90"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = LdapSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "escape_ldap" in updated.patch_diff
    assert "CWE-90" in updated.patch_explanation
