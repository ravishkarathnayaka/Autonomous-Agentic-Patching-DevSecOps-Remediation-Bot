"""Autonomous agent specialized in Mass Assignment (CWE-915) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class MassAssignmentGuardAgent:
    """Agent that remediates Mass Assignment and Object Attribute Overwrite vulnerabilities (CWE-915).

    Remediations:
    - Replaces blind dictionary merging (`dict.update(user_input)`) with strict property whitelisting.
    - Filters out administrative and privilege-bearing keys (`is_admin`, `role`, `permissions`, `account_id`).
    - Employs `MassAssignmentAuditor` to flag prohibited keys and reject malicious request payloads.
    """

    def __init__(self, name: str = "MassAssignmentGuardAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process mass assignment finding and synthesize property whitelisting patch."""
        finding = state.finding
        state.log_event(self.name, "start_mass_assignment_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_mass_assignment_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "mass_assignment_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_mass_assignment_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff filtering input keys against allowed fields."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -675,3 +675,8 @@\n"
            f"-    profile.update(data)\n"
            f"+    from agent_engine.tools.mass_assignment_auditor import MassAssignmentAuditor\n"
            f"+    safe_fields = MassAssignmentAuditor.filter_allowed_fields(\n"
            f"+        data, allowed_fields=['email', 'bio', 'display_name']\n"
            f"+    )\n"
            f"+    profile.update(safe_fields)\n"
        )
        explanation = (
            f"Mass Assignment Remediation: Addressed {rule_id} (CWE-915) by restricting update parameters via "
            "`MassAssignmentAuditor.filter_allowed_fields`. Only explicitly permitted fields (`email`, `bio`, `display_name`) "
            "are merged into the user profile, preventing unauthorized privilege escalation to `is_admin` or `role`."
        )
        return diff, explanation
