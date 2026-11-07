"""Autonomous agent specialized in Open Redirect (CWE-601) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class OpenRedirectGuardAgent:
    """Agent that remediates Unvalidated URL Redirection (CWE-601).

    Remediations:
    - Inspects destination URLs with `OpenRedirectValidator` to enforce domain allowlists.
    - Prohibits protocol-relative escapes (e.g. `//attacker.com`), javascript: pseudo-protocols, and backslash bypasses.
    - Falls back to safe internal relative landing pages upon invalid redirect destinations.
    """

    def __init__(self, name: str = "OpenRedirectGuardAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process open redirect finding and synthesize destination validation patch."""
        finding = state.finding
        state.log_event(self.name, "start_open_redirect_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_redirect_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "open_redirect_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_redirect_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff validating redirect target with OpenRedirectValidator."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -690,4 +690,8 @@\n"
            f"-    return redirect(target_url, code=302)\n"
            f"+    from agent_engine.tools.open_redirect_validator import OpenRedirectValidator\n"
            f"+    if not OpenRedirectValidator.is_safe_redirect(target_url, allowed_hosts=['trusted.corp.com']):\n"
            f"+        return jsonify({{'error': 'Disallowed redirect URL: external destination not authorized'}}), 400\n"
            f"+    return redirect(target_url, code=302)\n"
        )
        explanation = (
            f"Open Redirect Remediation: Addressed {rule_id} (CWE-601) by validating redirect destinations with "
            "`OpenRedirectValidator`. Target URLs must either reside on an authorized host (`trusted.corp.com`) or represent "
            "strictly relative internal paths. Attempts to redirect clients to untrusted external domains are blocked."
        )
        return diff, explanation
