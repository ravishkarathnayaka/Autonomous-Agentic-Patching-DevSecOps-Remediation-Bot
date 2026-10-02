"""Unit tests for Patch Agent prompt formatting and diff extraction."""

from agent_engine.agents.patch_agent import PatchAgent
from agent_engine.llm.client import MockLLMClient
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def _create_sample_state(rule_id="rules.python.security.sql_injection", cwe="CWE-89") -> RemediationState:
    finding = Finding(
        id="test-finding-1",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id=rule_id,
        title="SQL Injection Vulnerability",
        description="Untrusted user input concatenated into SQL query string.",
        severity=SeverityLevel.HIGH,
        cwe_ids=[cwe],
        cvss_score=8.9,
        file_path="target_repo/app.py",
        start_line=28,
        end_line=29,
        vulnerable_code="query = f'SELECT * FROM items WHERE name = {name}'"
    )
    return RemediationState(finding=finding, target_repo_path="target_repo")


def test_patch_agent_generates_sqli_patch():
    """Verify PatchAgent generates a clean unified diff for SQL injection finding."""
    client = MockLLMClient()
    agent = PatchAgent(llm_client=client)
    state = _create_sample_state(cwe="CWE-89")

    result = agent.execute(state)

    assert result.status == RemediationStatus.PATCH_GENERATED
    assert result.patch_diff is not None
    assert "--- a/target_repo/app.py" in result.patch_diff
    assert "+++" in result.patch_diff
    assert "?" in result.patch_diff  # Parameterized query replacement
    assert result.patch_explanation is not None
    assert "CWE-89" in result.patch_explanation


def test_patch_agent_retry_prompt_includes_error():
    """Verify PatchAgent includes prior verification error feedback during retries."""
    client = MockLLMClient()
    agent = PatchAgent(llm_client=client)
    state = _create_sample_state()
    state.retry_count = 1
    state.last_error_trace = "FAILED test_app.py::test_search_valid - sqlite3.OperationalError: near 'syntax error'"

    prompt = agent._build_prompt(state)
    assert "Previous Verification Attempt Failed!" in prompt
    assert "sqlite3.OperationalError" in prompt


def test_patch_agent_missing_diff_error():
    """Verify PatchAgent sets state to FAILED when LLM output lacks a diff."""
    class EmptyLLMClient(MockLLMClient):
        def generate(self, prompt: str, system_prompt=None, temperature=0.0) -> str:
            return "I cannot produce a diff right now."

    agent = PatchAgent(llm_client=EmptyLLMClient())
    state = _create_sample_state()
    result = agent.execute(state)

    assert result.status == RemediationStatus.FAILED
    assert "did not contain a valid unified diff" in (result.last_error_trace or "")
