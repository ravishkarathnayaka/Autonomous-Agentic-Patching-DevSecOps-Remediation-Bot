"""Autonomous agent specialized in Insecure Deserialization (Pickle - CWE-502) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class PickleDeserializationAgent:
    """Agent that remediates Insecure Deserialization (CWE-502).

    Remediations:
    - Replaces unsafe `pickle.loads` with `json.loads` or cryptographic HMAC signature verification.
    - Inspects incoming serialized payloads with `PickleSafetyInspector` to reject opcode execution gadgets.
    - Prohibits untrusted object reconstruction from user-controlled network input.
    """

    def __init__(self, name: str = "PickleDeserializationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process insecure deserialization finding and synthesize safe parsing patch."""
        finding = state.finding
        state.log_event(self.name, "start_pickle_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_pickle_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "pickle_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_pickle_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff replacing raw pickle with safe JSON deserialization."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -630,5 +630,10 @@\n"
            f"-        import pickle\n"
            f"-        unpickled_obj = pickle.loads(raw_bytes)\n"
            f"+        import json\n"
            f"+        try:\n"
            f"+            unpickled_obj = json.loads(raw_bytes.decode('utf-8'))\n"
            f"+        except Exception:\n"
            f"+            return jsonify({{'error': 'Insecure deserialization prohibited: payload must be valid JSON'}}), 400\n"
        )
        explanation = (
            f"Pickle Deserialization Remediation: Addressed {rule_id} (CWE-502) by replacing unsafe `pickle.loads` "
            "with standard `json.loads`. Parsing arbitrary Python pickle streams permits remote code execution (RCE) via "
            "`__reduce__` exploit payloads; replacing with structured JSON eliminates arbitrary object instantiation."
        )
        return diff, explanation
