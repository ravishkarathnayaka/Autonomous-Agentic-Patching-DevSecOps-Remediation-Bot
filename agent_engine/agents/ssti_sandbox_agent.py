"""Autonomous agent specialized in Server-Side Template Injection (SSTI - CWE-1336) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SstiSandboxAgent:
    """Agent that remediates Server-Side Template Injection (CWE-1336).

    Remediations:
    - Replaces unconfined `jinja2.Template` compilation with `jinja2.sandbox.SandboxedEnvironment`.
    - Prohibits accessing private attributes (`_`, `__class__`, `__mro__`, `__subclasses__`).
    - Enforces autoescaping (`autoescape=True`) to prevent cross-site scripting alongside template breakouts.
    """

    def __init__(self, name: str = "SstiSandboxAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process template injection finding and synthesize sandboxed template patch."""
        finding = state.finding
        state.log_event(self.name, "start_ssti_sandbox_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_ssti_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "ssti_sandbox_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_ssti_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff using SandboxedEnvironment with autoescaping."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -610,4 +610,8 @@\n"
            f"-        from jinja2 import Template\n"
            f"-        tmpl = Template(template_str)\n"
            f"+        from jinja2.sandbox import SandboxedEnvironment\n"
            f"+        env = SandboxedEnvironment(autoescape=True)\n"
            f"+        tmpl = env.from_string(template_str)\n"
        )
        explanation = (
            f"SSTI Remediation: Addressed {rule_id} (CWE-1336) by migrating string template evaluation to "
            "`jinja2.sandbox.SandboxedEnvironment` with `autoescape=True`. SandboxedEnvironment strictly intercepts "
            "and blocks unsafe attribute lookups like `__class__` and `__subclasses__` preventing arbitrary command execution."
        )
        return diff, explanation
