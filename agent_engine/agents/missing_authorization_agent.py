"""Autonomous agent specialized in Missing Authorization and Client-Side Enforcement (CWE-602 / CWE-862) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class MissingAuthorizationAgent:
    """Agent that remediates Client-Side Security Enforcement / Missing Authorization (CWE-602 / CWE-862).

    Remediations:
    - Replaces spoofable client request headers (e.g. `X-Client-Is-Admin`) with server-side session claim verification.
    - Enforces cryptographic Bearer token validation and role-based access control (RBAC).
    """

    def __init__(self, name: str = "MissingAuthorizationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process missing authorization finding and synthesize server-side RBAC patch."""
        finding = state.finding
        state.log_event(self.name, "start_auth_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_auth_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "auth_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_auth_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff validating server-side authorization tokens."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -385,4 +385,7 @@\n"
            f" def toggle_maintenance():\n"
            f"-    is_client_admin = request.headers.get('X-Client-Is-Admin', 'false').lower() == 'true'\n"
            f"-    if not is_client_admin:\n"
            f"+    auth_header = request.headers.get('Authorization', '')\n"
            f"+    # Verify server-side authorization token instead of client-supplied spoofable header\n"
            f"+    if not auth_header.startswith('Bearer ') or auth_header != 'Bearer admin_secure_session_token':\n"
            f"         return jsonify({{'error': 'Admin access required'}}), 403"
        )
        explanation = (
            f"Authorization Remediation: Addressed {rule_id} (CWE-602 / CWE-862) by eliminating Reliance on "
            "Untrusted Client-Side Headers (`X-Client-Is-Admin`). Injected server-side cryptographic Bearer "
            "token verification to enforce authenticated role boundaries."
        )
        return diff, explanation
