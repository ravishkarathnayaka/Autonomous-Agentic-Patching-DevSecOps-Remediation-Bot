from agent_engine.agents.idor_agent import IdorRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_idor_agent_remediation():
    finding = Finding(
        id="qualys-idor-01",
        scanner="qualys-was",
        finding_type=FindingType.DAST,
        rule_id="CWE-639",
        title="Insecure Direct Object Reference on Invoices",
        description="Users can download invoices belonging to other accounts by swapping invoice_id",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-639"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = IdorRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "current_user_id" in updated.patch_diff
    assert "owner_id != current_user_id" in updated.patch_diff
    assert "CWE-639" in updated.patch_explanation
