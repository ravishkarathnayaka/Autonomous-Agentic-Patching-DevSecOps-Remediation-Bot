"""Autonomous agent specialized in remediating DAST findings and HTTP security headers."""

import logging
from typing import Optional, Tuple
from agent_engine.state import Finding, RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class DASTSanitizerAgent:
    """Agent that handles dynamic application security flaws (OWASP ZAP findings).

    Synthesizes secure HTTP middleware headers:
    - Content-Security-Policy
    - Strict-Transport-Security (HSTS)
    - X-Content-Type-Options: nosniff
    - X-Frame-Options: DENY
    """

    def __init__(self, name: str = "DASTSanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process DAST finding and inject secure HTTP header middleware diff."""
        finding = state.finding
        state.log_event(self.name, "start_dast_remediation", {"rule_id": finding.rule_id})

        diff, explanation = self._synthesize_header_middleware(finding.file_path, finding.title)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "dast_remediated", {"diff_length": len(diff)})
        return state

    def _synthesize_header_middleware(self, file_path: str, title: str) -> Tuple[str, str]:
        """Produce unified diff injecting Flask after_request security headers."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -20,0 +21,8 @@\n"
            f"+@app.after_request\n"
            f"+def set_security_headers(response):\n"
            f"+    response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
            f"+    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'\n"
            f"+    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
            f"+    response.headers['X-Frame-Options'] = 'DENY'\n"
            f"+    return response"
        )

        explanation = (
            "DAST Mitigation: Injected centralized HTTP security header middleware (`@app.after_request`). "
            "Enforces strict Content-Security-Policy (CSP), HSTS transport encryption, nosniff MIME typing, "
            "and clickjacking prevention per OWASP Top 10 A05:2021 Security Misconfiguration standards."
        )

        return diff, explanation
