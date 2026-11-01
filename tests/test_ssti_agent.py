from agent_engine.agents.ssti_agent import SSTIRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_ssti_remediation():
    finding = Finding(
        id="semgrep-ssti-format",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-1336",
        title="Server-Side Template Injection via string formatting",
        description="Dynamic string formatting passed to render_template_string",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-1336"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = SSTIRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "render_template_string(template, name=name)" in updated.patch_diff
    assert "CWE-1336" in updated.patch_explanation
