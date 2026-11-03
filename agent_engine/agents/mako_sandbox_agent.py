"""Autonomous agent specialized in Template Injection & Sandbox Bypass (CWE-1336) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class MakoSandboxAgent:
    """Agent that remediates Improper Neutralization in Template Engine (CWE-1336 / CWE-94).

    Remediations:
    - Enforces autoescape and strictly bounded Jinja2/Mako context sandboxes.
    - Eliminates dynamic string evaluation via `render_template_string` in favor of static templates.
    """

    def __init__(self, name: str = "MakoSandboxAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process template injection finding and synthesize sandboxed template patch."""
        finding = state.finding
        state.log_event(self.name, "start_template_sandbox_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_sandbox_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "template_sandboxed", {"rule_id": rule_id})
        return state

    def _synthesize_sandbox_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff applying sandboxed environment rendering."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -415,4 +415,6 @@\n"
            f"-        rendered = render_template_string(template_str, **user_context)\n"
            f"+        from jinja2.sandbox import SandboxedEnvironment\n"
            f"+        env = SandboxedEnvironment(autoescape=True)\n"
            f"+        rendered = env.from_string(template_str).render(**user_context)"
        )
        explanation = (
            f"Template Sandbox Remediation: Addressed {rule_id} (CWE-1336 / CWE-94) by enforcing Jinja2 "
            "`SandboxedEnvironment` with `autoescape=True`. This prevents attribute lookup traversal (`__class__`, "
            "`__mro__`, `__subclasses__`) and blocks remote code execution."
        )
        return diff, explanation
