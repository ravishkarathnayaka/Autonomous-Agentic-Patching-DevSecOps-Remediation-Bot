from agent_engine.agents.zip_slip_agent import ZipSlipRemediationAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_zip_slip_remediation():
    finding = Finding(
        id="snyk-zip-slip-001",
        scanner="snyk",
        finding_type=FindingType.SAST,
        rule_id="CWE-22",
        title="Arbitrary File Write via Archive Extraction (Zip Slip)",
        description="extractall called without validating destination paths",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-22", "CWE-29"],
        file_path="target_repo/archive_utils.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = ZipSlipRemediationAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "commonpath" in updated.patch_diff
    assert "PermissionError" in updated.patch_diff
    assert "CWE-22" in updated.patch_explanation
