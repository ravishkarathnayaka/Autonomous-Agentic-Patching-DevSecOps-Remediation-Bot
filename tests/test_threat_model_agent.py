from agent_engine.agents.threat_model_agent import ThreatModelAgent
from agent_engine.state import Finding, FindingType, RemediationState, SeverityLevel


def test_threat_model_agent_sqli():
    finding = Finding(
        id="test-sqli",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="sqli-rule",
        title="SQL Injection",
        description="SQL injection in endpoint",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        file_path="app.py"
    )

    agent = ThreatModelAgent()
    analysis = agent.analyze(finding)

    assert analysis["stride_category"] == "Tampering"
    assert "CWE-89" in analysis["cwe"]
    assert float(analysis["dread_score"]) >= 8.0


def test_threat_model_agent_execution_updates_explanation():
    finding = Finding(
        id="test-cmdi",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="cmdi-rule",
        title="Command Injection",
        description="Command injection flaw",
        severity=SeverityLevel.CRITICAL,
        cwe_ids=["CWE-78"],
        file_path="app.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    state.patch_explanation = "Base patch explanation"

    agent = ThreatModelAgent()
    updated = agent.execute(state)

    assert "STRIDE Threat Modeling Analysis" in updated.patch_explanation
    assert "Elevation of Privilege" in updated.patch_explanation
