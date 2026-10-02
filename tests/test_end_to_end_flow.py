"""Integration tests verifying end-to-end multi-agent remediation lifecycle."""

from pathlib import Path
import shutil
import subprocess
import pytest

from agent_engine.graph import RemediationGraph
from agent_engine.llm.client import MockLLMClient
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel
from agent_engine.tools.sandbox_executor import SandboxExecutor

ROOT_DIR = Path(__file__).parent.parent
TARGET_REPO_SOURCE = ROOT_DIR / "target_repo"


@pytest.fixture
def temp_target_repo(tmp_path):
    """Create a temporary git repository initialized with sample vulnerable app."""
    repo_dir = tmp_path / "target_repo"
    shutil.copytree(TARGET_REPO_SOURCE, repo_dir)

    # Initialize git repo in the temporary directory
    subprocess.run(["git", "init", "-b", "main"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "DevSecOpsBot"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "bot@devsecops.local"], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=str(repo_dir), check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "Initial vulnerable commit"], cwd=str(repo_dir), check=True, capture_output=True)

    return repo_dir


def test_end_to_end_sqli_remediation(temp_target_repo):
    """Verify complete Triage -> Patch -> Sandbox Verify -> PR workflow for SQLi."""
    finding = Finding(
        id="finding-sqli-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="rules.python.security.sqlite_sql_injection",
        title="SQL Injection in /items endpoint",
        description="User-controllable input formatted directly into raw SQL query allows SQL Injection.",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        cvss_score=9.8,
        file_path="app.py",
        start_line=28,
        end_line=29,
        vulnerable_code="    query = f\"SELECT * FROM items WHERE name = '{name}'\"\n    cursor.execute(query)"
    )

    llm_client = MockLLMClient(simulate_retry_failure=False)
    executor = SandboxExecutor(force_local=True)

    state = RemediationState(
        finding=finding,
        target_repo_path=str(temp_target_repo),
        max_retries=3
    )

    graph = RemediationGraph(
        llm_client=llm_client,
        sandbox_executor=executor,
        max_retries=3,
        test_file="test_app.py"
    )

    final_state = graph.run(state)

    # 1. Verify successful terminal state
    assert final_state.status == RemediationStatus.PR_READY
    assert final_state.retry_count == 0

    # 2. Verify verification results
    assert len(final_state.verification_results) == 1
    assert final_state.verification_results[0].passed is True
    assert final_state.verification_results[0].functional_tests_passed is True

    # 3. Verify patch diff contents
    assert final_state.patch_diff is not None
    assert "?" in final_state.patch_diff

    # 4. Verify PR metadata
    assert final_state.pr_branch is not None
    assert "security/fix-cwe-89" in final_state.pr_branch
    assert final_state.pr_title is not None
    assert "CWE-89" in final_state.pr_title
    assert final_state.commit_sha is not None
    assert final_state.pr_body is not None
    assert "Autonomous Security Remediation Pull Request" in final_state.pr_body
    assert "CWE-89" in final_state.pr_body

    # 5. Verify audit trail was logged
    agents_in_trail = {event["agent"] for event in final_state.audit_trail}
    assert "TriageAgent" in agents_in_trail
    assert "PatchAgent" in agents_in_trail
    assert "VerifierAgent" in agents_in_trail
    assert "PRAgent" in agents_in_trail


def test_end_to_end_self_healing_retry_loop(temp_target_repo):
    """Verify that a broken initial patch triggers a retry that subsequently passes."""
    finding = Finding(
        id="finding-retry-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="rules.python.security.sqlite_sql_injection",
        title="SQL Injection in /items endpoint",
        description="Untrusted query string parameter.",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-89"],
        cvss_score=9.8,
        file_path="app.py",
        start_line=28,
        end_line=29,
        vulnerable_code="    query = f\"SELECT * FROM items WHERE name = '{name}'\"\n    cursor.execute(query)"
    )

    # Instruct mock provider to simulate failure on call 1
    llm_client = MockLLMClient(simulate_retry_failure=True)
    executor = SandboxExecutor(force_local=True)

    state = RemediationState(
        finding=finding,
        target_repo_path=str(temp_target_repo),
        max_retries=3
    )

    graph = RemediationGraph(
        llm_client=llm_client,
        sandbox_executor=executor,
        max_retries=3,
        test_file="test_app.py"
    )

    final_state = graph.run(state)

    # Verification should succeed on retry attempt 1
    assert final_state.status == RemediationStatus.PR_READY
    assert final_state.retry_count == 1
    assert len(final_state.verification_results) == 2
    # First attempt failed
    assert final_state.verification_results[0].passed is False
    # Second attempt passed
    assert final_state.verification_results[1].passed is True
