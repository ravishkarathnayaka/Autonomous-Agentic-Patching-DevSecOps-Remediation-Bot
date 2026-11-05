"""Autonomous agent specialized in Regular Expression Denial of Service (ReDoS - CWE-1333) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class RegexTimeoutAgent:
    """Agent that remediates Regular Expression Denial of Service (CWE-1333).

    Remediations:
    - Enforces hard character length limits on user input before evaluation against regular expressions.
    - Disallows catastrophic backtracking constructs (e.g., nested quantifiers `(a+)+` or `([a-zA-Z0-9]+)*`).
    - Uses execution timeouts or atomic grouping to prevent event loop starvation.
    """

    def __init__(self, name: str = "RegexTimeoutAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process ReDoS finding and synthesize regex execution safety patch."""
        finding = state.finding
        state.log_event(self.name, "start_redos_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_redos_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "redos_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_redos_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff restricting input length and complex backtracking."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -540,5 +540,10 @@\n"
            f"-    match = re.search(user_pattern, text)\n"
            f"+    if len(user_pattern) > 200 or len(text) > 5000:\n"
            f"+        return jsonify({{'error': 'Input length exceeds safe regex evaluation limit'}}), 400\n"
            f"+    from agent_engine.tools.regex_complexity_auditor import RegexComplexityAuditor\n"
            f"+    if not RegexComplexityAuditor.is_safe_pattern(user_pattern):\n"
            f"+        return jsonify({{'error': 'Disallowed dangerous regular expression structure'}}), 400\n"
            f"+    match = re.search(user_pattern, text)\n"
        )
        explanation = (
            f"ReDoS Remediation: Addressed {rule_id} (CWE-1333) by enforcing input size constraints and analyzing "
            "regular expression patterns for catastrophic backtracking patterns using `RegexComplexityAuditor`. "
            "Prevents unbounded CPU consumption and DoS."
        )
        return diff, explanation
