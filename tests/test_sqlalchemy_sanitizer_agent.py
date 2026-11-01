from agent_engine.agents.sqlalchemy_sanitizer_agent import SQLAlchemySanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_sqla_sanitizer_remediation():
    finding = Finding(
        id="semgrep-sqli-raw-concat",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-89",
        title="SQL Injection via string formatting",
        description="User parameter concatenated directly into SQL cursor execute query",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-89"],
        file_path="target_repo/app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = SQLAlchemySanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "WHERE name = ?" in updated.patch_diff
    assert "cursor.execute(query, (name,))" in updated.patch_diff
    assert "CWE-89" in updated.patch_explanation
