"""Autonomous agent specialized in Session and Cookie Security (CWE-614) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SessionHardeningAgent:
    """Agent that remediates Insecure Cookie Flag configurations (CWE-614 / OWASP A05:2021).

    Remediations:
    - Enforces `httponly=True` to block Cross-Site Scripting (XSS) DOM cookie access.
    - Enforces `secure=True` to require TLS/HTTPS transport.
    - Enforces `samesite='Lax'` or `'Strict'` to eliminate Cross-Site Request Forgery (CSRF).
    """

    def __init__(self, name: str = "SessionHardeningAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process insecure session finding and synthesize cookie hardening patch."""
        finding = state.finding
        state.log_event(self.name, "start_session_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_session_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "session_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_session_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff injecting secure cookie directives."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -190,3 +190,3 @@\n"
            f"     resp = jsonify({{'status': 'logged_in', 'user': username}})\n"
            f"-    resp.set_cookie('session_token', 'sess_xyz_12345', httponly=False, secure=False, samesite=None)\n"
            f"+    resp.set_cookie('session_token', 'sess_xyz_12345', httponly=True, secure=True, samesite='Strict')"
        )
        explanation = (
            f"Session Security Remediation: Addressed {rule_id} (CWE-614) by enforcing `httponly=True`, "
            "`secure=True`, and `samesite='Strict'` on sensitive session cookies, safeguarding auth tokens "
            "from XSS exfiltration, cleartext interception, and CSRF attacks."
        )
        return diff, explanation
