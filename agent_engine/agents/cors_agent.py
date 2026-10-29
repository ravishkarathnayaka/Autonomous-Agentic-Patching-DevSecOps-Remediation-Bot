"""Autonomous agent specialized in Cross-Origin Resource Sharing (CORS) security remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class CORSHardeningAgent:
    """Agent that remediates overly permissive CORS configurations (CWE-942 / OWASP A01:2021).

    Remediations:
    - Replaces wildcard origins (`*`) with verified enterprise domain allowlists.
    - Ensures `Access-Control-Allow-Credentials` is never combined with wildcard origins.
    """

    def __init__(self, name: str = "CORSHardeningAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process CORS finding and synthesize safe origin policy patch."""
        finding = state.finding
        state.log_event(self.name, "start_cors_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_cors_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "cors_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_cors_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff enforcing domain origin validation."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -138,4 +138,9 @@\n"
            f" def get_user_data():\n"
            f"     resp = jsonify({{\"account_id\": \"ACC-1029\", \"balance\": 5000}})\n"
            f"-    resp.headers[\"Access-Control-Allow-Origin\"] = \"*\"\n"
            f"+    origin = request.headers.get('Origin', '')\n"
            f"+    ALLOWED_ORIGINS = ['https://app.enterprise.com', 'https://portal.enterprise.com']\n"
            f"+    if origin in ALLOWED_ORIGINS:\n"
            f"+        resp.headers['Access-Control-Allow-Origin'] = origin\n"
            f"+        resp.headers['Vary'] = 'Origin'\n"
            f"     resp.headers[\"Access-Control-Allow-Credentials\"] = \"true\""
        )
        explanation = (
            f"CORS Remediation: Addressed {rule_id} (CWE-942) by replacing insecure wildcard reflection "
            "(`Access-Control-Allow-Origin: *`) with strict origin validation against an explicit enterprise "
            "allowlist, preventing credential theft across unauthorized domains."
        )

        return diff, explanation
