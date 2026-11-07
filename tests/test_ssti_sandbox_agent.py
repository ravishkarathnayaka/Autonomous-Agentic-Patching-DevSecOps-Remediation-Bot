from agent_engine.agents.ssti_sandbox_agent import SstiSandboxAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_ssti_sandbox_agent_remediation():
    finding = Finding(
        id="codeql-ssti-01",
        scanner="codeql",
        finding_type=FindingType.SAST,
        rule_id="CWE-1336",
        title="Server-Side Template Injection via Jinja2",
        description="Unsanitized user template string evaluation allows remote code execution",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-1336", "CWE-94"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = SstiSandboxAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "SandboxedEnvironment" in updated.patch_diff
    assert "autoescape=True" in updated.patch_diff
    assert "CWE-1336" in updated.patch_explanation
