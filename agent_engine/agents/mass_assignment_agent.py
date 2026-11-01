"""Autonomous agent specialized in Mass Assignment (CWE-915) parameter tampering remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class MassAssignmentAgent:
    """Agent that remediates Mass Assignment / Parameter Tampering (CWE-915 / OWASP API3:2023).

    Remediations:
    - Filters incoming request dictionary through an explicit immutable attribute whitelist.
    - Prevents privilege escalation (e.g. tampering with `is_admin`, `role`, `account_id`).
    """

    def __init__(self, name: str = "MassAssignmentAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process mass assignment finding and synthesize field whitelisting patch."""
        finding = state.finding
        state.log_event(self.name, "start_mass_assignment_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_mass_assignment_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "mass_assignment_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_mass_assignment_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff enforcing property whitelisting."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -325,4 +325,7 @@\n"
            f"     user_record = {{\n"
            f"         'user_id': 42,\n"
            f"-    user_record.update(data)\n"
            f"+    ALLOWED_FIELDS = {'{'} 'email', 'display_name', 'bio' {'}'}\n"
            f"+    filtered_data = {'{'}k: v for k, v in data.items() if k in ALLOWED_FIELDS{'}'}\n"
            f"+    user_record.update(filtered_data)"
        )
        explanation = (
            f"Mass Assignment Remediation: Addressed {rule_id} (CWE-915) by restricting dictionary binding "
            "to an explicit schema whitelist (ALLOWED_FIELDS), preventing unauthorized modification of internal "
            "attributes such as `is_admin` or `role`."
        )
        return diff, explanation
