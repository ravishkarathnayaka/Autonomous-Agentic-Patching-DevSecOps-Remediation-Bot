from agent_engine.agents.secret_remediation_agent import SecretRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_secret_remediation_agent_basic():
    finding = Finding(
        id="gl-aws-secret-01",
        scanner="gitleaks",
        finding_type=FindingType.SECRET,
        rule_id="aws-access-token",
        title="AWS Access Token Leaked",
        description="Hardcoded AWS key identified in source code",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-798"],
        cvss_score=9.5,
        file_path="target_repo/config.py",
        start_line=12,
        end_line=12,
        vulnerable_code='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'
    )

    state = RemediationState(finding=finding, target_repo_path="target_repo")
    agent = SecretRemediationAgent()
    updated_state = agent.execute(state)

    assert updated_state.status == RemediationStatus.PATCH_GENERATED
    assert updated_state.patch_diff is not None
    assert "os.environ.get('AWS_ACCESS_TOKEN'" in updated_state.patch_diff
    assert "AKIAIOSFODNN7EXAMPLE" not in updated_state.patch_diff.splitlines()[-1]
    assert "CWE-798" in updated_state.patch_explanation


def test_secret_remediation_agent_empty_snippet():
    finding = Finding(
        id="gl-empty",
        scanner="gitleaks",
        finding_type=FindingType.SECRET,
        rule_id="generic-secret",
        title="Empty secret finding",
        description="Empty",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-798"],
        file_path="target_repo/config.py",
        start_line=1,
        end_line=1,
        vulnerable_code=""
    )

    state = RemediationState(finding=finding, target_repo_path="target_repo")
    agent = SecretRemediationAgent()
    updated_state = agent.execute(state)

    assert updated_state.status == RemediationStatus.FAILED
