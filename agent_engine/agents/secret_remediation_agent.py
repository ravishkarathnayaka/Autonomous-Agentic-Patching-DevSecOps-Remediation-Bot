"""Autonomous agent specialized in remediating hardcoded secrets and credentials."""

import logging
import re
from typing import Optional, Tuple
from agent_engine.state import Finding, RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SecretRemediationAgent:
    """Agent that handles leaked credentials (CWE-798 / Gitleaks findings).

    Performs surgical remediation:
    1. Replaces hardcoded string literal with environment variable lookup (os.environ.get).
    2. Suggests corresponding variable name for .env.example.
    3. Emits unified diff eliminating the secret from source code.
    """

    def __init__(self, name: str = "SecretRemediationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process secret finding and synthesize unified diff replacing literal with env var."""
        finding = state.finding
        state.log_event(self.name, "start_secret_remediation", {"rule_id": finding.rule_id})

        vulnerable_code = finding.vulnerable_code or ""
        target_file = finding.file_path

        # Generate a descriptive environment variable name from rule ID or secret context
        env_var_name = self._generate_env_var_name(finding.rule_id)

        # Detect secret pattern in snippet (quoted string assignment)
        diff, explanation = self._generate_redaction_diff(
            file_path=target_file,
            vulnerable_code=vulnerable_code,
            env_var_name=env_var_name,
            line_no=finding.start_line
        )

        if not diff:
            state.status = RemediationStatus.FAILED
            state.last_error_trace = "Could not automatically isolate hardcoded secret token in code snippet"
            state.log_event(self.name, "remediation_failed", {"error": state.last_error_trace})
            return state

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "secret_remediated", {
            "env_var_name": env_var_name,
            "diff_length": len(diff)
        })
        return state

    def _generate_env_var_name(self, rule_id: str) -> str:
        """Generate uppercase environment variable name."""
        clean = re.sub(r"[^a-zA-Z0-9]+", "_", rule_id).upper().strip("_")
        if not clean.endswith("_KEY") and not clean.endswith("_TOKEN") and not clean.endswith("_SECRET"):
            clean = f"{clean}_SECRET"
        return clean

    def _generate_redaction_diff(
        self,
        file_path: str,
        vulnerable_code: str,
        env_var_name: str,
        line_no: int
    ) -> Tuple[Optional[str], str]:
        """Produce unified diff swapping string literal with os.environ.get."""
        lines = vulnerable_code.strip().splitlines()
        if not lines:
            return None, "Empty code snippet"

        orig_line = lines[0]
        # Match pattern: var_name = "secret" or var_name = 'secret'
        match = re.match(r"^(\s*[\w_]+\s*=\s*)(['\"][^'\"]+['\"])(.*)$", orig_line)
        if match:
            prefix = match.group(1)
            suffix = match.group(3)
            remediated_line = f"{prefix}os.environ.get('{env_var_name}', ''){suffix}"
        else:
            # Fallback replacement
            remediated_line = f"os.environ.get('{env_var_name}', '')"

        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -{line_no},1 +{line_no},1 @@\n"
            f"-{orig_line}\n"
            f"+{remediated_line}"
        )

        explanation = (
            f"Redacted plaintext secret token (CWE-798). Replaced hardcoded literal with secure "
            f"runtime environment variable lookup `os.environ.get('{env_var_name}')`. "
            f"Ensure '{env_var_name}' is injected via secret store or vault in production."
        )

        return diff, explanation
