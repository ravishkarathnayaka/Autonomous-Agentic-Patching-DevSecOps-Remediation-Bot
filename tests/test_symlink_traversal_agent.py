from agent_engine.agents.symlink_traversal_agent import SymlinkTraversalAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_symlink_traversal_remediation():
    finding = Finding(
        id="insightappsec-symlink-01",
        scanner="insightappsec",
        finding_type=FindingType.DAST,
        rule_id="CWE-59",
        title="Improper Link Resolution Before File Access",
        description="Arbitrary file reading via symbolic links",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-59", "CWE-22"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = SymlinkTraversalAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "commonpath" in updated.patch_diff
    assert "Symlink traversal blocked" in updated.patch_diff
    assert "CWE-59" in updated.patch_explanation
