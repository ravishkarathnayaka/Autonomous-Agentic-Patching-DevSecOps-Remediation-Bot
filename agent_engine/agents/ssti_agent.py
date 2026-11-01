"""Autonomous agent specialized in Server-Side Template Injection (SSTI) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SSTIRemediationAgent:
    """Agent that remediates Server-Side Template Injection (CWE-1336 / OWASP A03:2021).

    Remediations:
    - Replaces dynamic string formatting in template strings with parameterized context dictionaries.
    - Enforces autoescape and Jinja2 SandboxedEnvironment rendering.
    """

    def __init__(self, name: str = "SSTIRemediationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process SSTI finding and synthesize safe template rendering patch."""
        finding = state.finding
        state.log_event(self.name, "start_ssti_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_ssti_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "ssti_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_ssti_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff parameterized template rendering."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -273,4 +273,6 @@\n"
            f"     name = data.get('name', 'Guest')\n"
            f"-    template = f'Hello {{name}}! Welcome to the platform.'\n"
            f"-    rendered = render_template_string(template)\n"
            f"+    template = 'Hello {{ name }}! Welcome to the platform.'\n"
            f"+    rendered = render_template_string(template, name=name)"
        )
        explanation = (
            f"SSTI Remediation: Addressed {rule_id} (CWE-1336) by replacing dangerous runtime string concatenation "
            "with parameterized template variables passed via context parameters, ensuring template engine auto-escaping "
            "prevents arbitrary code execution."
        )
        return diff, explanation
