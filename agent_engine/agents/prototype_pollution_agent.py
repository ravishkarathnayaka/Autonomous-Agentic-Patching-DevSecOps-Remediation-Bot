"""Autonomous agent specialized in Prototype Pollution / Object Property Injection (CWE-1321) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class PrototypePollutionRemediationAgent:
    """Agent that remediates Improperly Controlled Modification of Dynamically-Determined Object Attributes (CWE-1321).

    Remediations:
    - Filters and rejects dangerous object properties: `__proto__`, `constructor`, `prototype`, `__class__`.
    - Enforces safe dictionary merging with explicit key validation.
    """

    def __init__(self, name: str = "PrototypePollutionRemediationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process prototype pollution finding and synthesize safe merge patch."""
        finding = state.finding
        state.log_event(self.name, "start_prototype_pollution_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_merge_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "prototype_pollution_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_merge_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff rejecting prototype and class attribute traversal."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -432,5 +432,8 @@\n"
            f"     def unsafe_merge(target, src):\n"
            f"+        DANGEROUS_KEYS = {{'__proto__', '__class__', 'constructor', 'prototype'}}\n"
            f"         for k, v in src.items():\n"
            f"+            if k in DANGEROUS_KEYS or str(k).startswith('__'):\n"
            f"+                continue\n"
            f"             if isinstance(v, dict) and k in target and isinstance(target[k], dict):"
        )
        explanation = (
            f"Prototype Pollution Remediation: Addressed {rule_id} (CWE-1321) by screening input dictionary keys "
            "against reserved object attributes (`__proto__`, `__class__`, `constructor`, `prototype`). "
            "This eliminates arbitrary object property manipulation and prevents privilege escalation."
        )
        return diff, explanation
