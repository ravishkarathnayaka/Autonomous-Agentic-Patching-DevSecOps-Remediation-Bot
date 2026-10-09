"""Unit tests for TriageAgent integration with RemediationPolicyEngine."""

from pathlib import Path
from agent_engine.agents.triage_agent import TriageAgent
from agent_engine.policy_engine import RemediationPolicy, RemediationPolicyEngine
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_triage_blocks_finding_violating_policy():
    policy = RemediationPolicy({"min_cvss": 9.0})  # Only critical CVSS >= 9.0
    policy_engine = RemediationPolicyEngine(policy)
    agent = TriageAgent(policy_engine=policy_engine)

    finding = Finding(
        id="finding-test-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="rules.sqli",
        title="SQL Injection",
        description="SQL injection in query",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        cvss_score=7.5,  # Below 9.0 threshold
        file_path="target_repo/app.py",
        start_line=28,
        end_line=29
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    final_state = agent.execute(state)

    assert final_state.status == RemediationStatus.FAILED
    assert "Blocked by DevSecOps Policy" in (final_state.last_error_trace or "")


def test_triage_allows_finding_conforming_to_policy():
    policy = RemediationPolicy({"min_cvss": 5.0})
    policy_engine = RemediationPolicyEngine(policy)
    agent = TriageAgent(policy_engine=policy_engine)

    finding = Finding(
        id="finding-test-02",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="rules.sqli",
        title="SQL Injection",
        description="SQL injection in query",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        cvss_score=8.5,
        file_path="target_repo/app.py",
        start_line=28,
        end_line=29
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    final_state = agent.execute(state)

    assert final_state.status == RemediationStatus.TRIAGED
    assert final_state.finding.ast_context is not None
