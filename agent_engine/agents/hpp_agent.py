"""Autonomous agent specialized in HTTP Parameter Pollution (HPP - CWE-235) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class HppRemediationAgent:
    """Agent that remediates HTTP Parameter Pollution (CWE-235).

    Remediations:
    - Replaces naive query parameter access (`request.args.get()`) with strict multiplicity checks (`request.args.getlist()`).
    - Enforces single-value invariants on critical transaction parameters (e.g., recipient, amount, account_id).
    - Blocks unexpected duplicate keys that could bypass gateway WAF validation or lead to transaction tampering.
    """

    def __init__(self, name: str = "HppRemediationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process HTTP Parameter Pollution finding and synthesize parameter validation patch."""
        finding = state.finding
        state.log_event(self.name, "start_hpp_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_hpp_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "hpp_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_hpp_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff rejecting duplicate query parameter keys."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -510,5 +510,10 @@\n"
            f"-    recipient = request.args.get('recipient')\n"
            f"-    amount = request.args.get('amount')\n"
            f"+    recipients = request.args.getlist('recipient')\n"
            f"+    amounts = request.args.getlist('amount')\n"
            f"+    if len(recipients) > 1 or len(amounts) > 1:\n"
            f"+        return jsonify({{'error': 'HTTP Parameter Pollution detected: duplicate parameters'}}), 400\n"
            f"+    recipient = recipients[0] if recipients else None\n"
            f"+    amount = amounts[0] if amounts else None\n"
        )
        explanation = (
            f"HTTP Parameter Pollution Remediation: Addressed {rule_id} (CWE-235) by inspecting parameter "
            "multiplicity with `request.args.getlist()`. If duplicate parameter keys are encountered, the request "
            "is rejected with status 400 to prevent parameter injection bypasses."
        )
        return diff, explanation
