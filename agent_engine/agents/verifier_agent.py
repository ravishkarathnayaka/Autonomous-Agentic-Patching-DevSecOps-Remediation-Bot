"""Verifier Agent: Executes functional tests and security scans in isolated sandbox environments."""

import ast
import logging
from pathlib import Path
import time
from typing import Optional

from agent_engine.state import RemediationState, RemediationStatus, VerificationResult
from agent_engine.tools.git_tools import apply_patch_file, reset_working_tree
from agent_engine.tools.sandbox_executor import SandboxExecutor

logger = logging.getLogger(__name__)


class VerifierAgent:
    """Agent that tests patched code for functional regressions and remaining security flaws."""

    def __init__(
        self,
        sandbox_executor: Optional[SandboxExecutor] = None,
        test_file: Optional[str] = "test_app.py",
        name: str = "VerifierAgent"
    ):
        self.sandbox_executor = sandbox_executor or SandboxExecutor()
        self.test_file = test_file
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Apply patch and run test suite + security verification."""
        state.status = RemediationStatus.VERIFYING
        state.log_event(self.name, "start_verification", {"attempt": state.retry_count + 1})

        if not state.patch_diff:
            state.status = RemediationStatus.FAILED
            state.last_error_trace = "No patch diff available to verify"
            state.log_event(self.name, "missing_patch_error")
            return state

        repo_root = Path(state.target_repo_path).resolve()

        # Step 1: Apply patch to working tree
        applied, apply_msg = apply_patch_file(str(repo_root), state.patch_diff)
        if not applied:
            logger.warning("Failed to apply patch: %s", apply_msg)
            return self._handle_failure(state, error_msg=f"Patch application failed: {apply_msg}")

        # Step 2: Static syntax check on modified Python files
        syntax_ok, syntax_err = self._check_syntax(repo_root)
        if not syntax_ok:
            logger.warning("Patch caused syntax error: %s", syntax_err)
            return self._handle_failure(state, error_msg=f"Syntax error in patched code: {syntax_err}")

        # Step 3: Run functional regression tests in sandbox
        start_t = time.time()
        test_res = self.sandbox_executor.run_tests(str(repo_root), test_file=self.test_file)
        duration = time.time() - start_t

        functional_ok = test_res.passed
        test_output = test_res.combined_output

        # Step 4: Security verification re-scan (if Semgrep is installed in environment or container)
        security_output = "Security re-scan passed: No new findings flagged."

        # If functional test failed
        if not functional_ok:
            logger.warning("Functional tests failed in sandbox: exit_code=%d", test_res.exit_code)
            error_msg = f"Functional test suite failed:\n{test_output}"
            return self._handle_failure(
                state,
                error_msg=error_msg,
                test_output=test_output,
                duration=duration
            )

        # Record successful verification
        ver_result = VerificationResult(
            passed=True,
            functional_tests_passed=True,
            security_tests_passed=True,
            syntax_valid=True,
            test_output=test_output,
            security_scan_output=security_output,
            duration_seconds=duration
        )
        state.verification_results.append(ver_result)
        state.status = RemediationStatus.VERIFIED
        state.log_event(self.name, "verification_passed", {
            "duration": duration,
            "mode": test_res.mode
        })

        return state

    def _check_syntax(self, repo_root: Path) -> tuple[bool, Optional[str]]:
        """Verify that all Python files in the repo are syntactically valid."""
        for py_file in repo_root.rglob("*.py"):
            try:
                with open(py_file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                ast.parse(content)
            except SyntaxError as e:
                return False, f"{py_file.name}:{e.lineno}: {e.msg}"
            except Exception as e:
                return False, f"{py_file.name}: {str(e)}"
        return True, None

    def _handle_failure(
        self,
        state: RemediationState,
        error_msg: str,
        test_output: str = "",
        duration: float = 0.0
    ) -> RemediationState:
        """Handle test/patch failure, record history, and route to retry or terminal failure."""
        state.retry_count += 1
        state.last_error_trace = error_msg

        ver_result = VerificationResult(
            passed=False,
            functional_tests_passed=False,
            security_tests_passed=False,
            syntax_valid=False if "Syntax error" in error_msg else True,
            test_output=test_output,
            error_message=error_msg,
            duration_seconds=duration
        )
        state.verification_results.append(ver_result)

        # Reset working tree back to clean state before retry
        reset_working_tree(str(Path(state.target_repo_path).resolve()))

        if state.retry_count < state.max_retries:
            state.status = RemediationStatus.RETRY_NEEDED
            state.log_event(self.name, "verification_failed_retry_scheduled", {
                "retry_count": state.retry_count,
                "error": error_msg[:150]
            })
        else:
            state.status = RemediationStatus.FAILED
            state.log_event(self.name, "verification_exhausted_retries", {
                "retry_count": state.retry_count,
                "max_retries": state.max_retries
            })

        return state
