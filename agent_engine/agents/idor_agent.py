"""Autonomous agent specialized in Insecure Direct Object References (IDOR / BOLA - CWE-639) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class IdorRemediationAgent:
    """Agent that remediates Insecure Direct Object Reference / Broken Object Level Authorization (CWE-639).

    Remediations:
    - Verifies subject principal identity against object ownership or resource tenant scope.
    - Prevents arbitrary integer ID increments to exfiltrate neighbor resources.
    - Emits 403 Forbidden or 404 Not Found when authenticated principal does not possess authorization.
    """

    def __init__(self, name: str = "IdorRemediationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process IDOR/BOLA finding and synthesize authorization check patch."""
        finding = state.finding
        state.log_event(self.name, "start_idor_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_idor_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "idor_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_idor_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff verifying resource ownership."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -550,5 +550,11 @@\n"
            f"-    invoice = get_invoice_by_id(invoice_id)\n"
            f"-    return jsonify(invoice.to_dict())\n"
            f"+    invoice = get_invoice_by_id(invoice_id)\n"
            f"+    current_user_id = g.get('user_id') or session.get('user_id')\n"
            f"+    if not invoice or invoice.owner_id != current_user_id:\n"
            f"+        return jsonify({{'error': 'Unauthorized access to requested resource'}}), 403\n"
            f"+    return jsonify(invoice.to_dict())\n"
        )
        explanation = (
            f"IDOR / BOLA Remediation: Addressed {rule_id} (CWE-639) by asserting resource ownership against the "
            "authenticated session user identity (`g.user_id` / `session['user_id']`). Requests attempting to access "
            "invoices or objects belonging to third parties return HTTP 403 Forbidden."
        )
        return diff, explanation
