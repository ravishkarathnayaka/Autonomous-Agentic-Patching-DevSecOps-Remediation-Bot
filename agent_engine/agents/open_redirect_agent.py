"""Autonomous agent specialized in Open Redirect (CWE-601) security remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class OpenRedirectAgent:
    """Agent that remediates Open Redirect vulnerabilities (CWE-601 / OWASP A01:2021).

    Remediations:
    - Validates target redirect URLs against an approved domain whitelist or relative path assertion.
    - Prevents schema-relative protocol injection (e.g. `//attacker.com`).
    """

    def __init__(self, name: str = "OpenRedirectAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process open redirect finding and synthesize safe redirect patch."""
        finding = state.finding
        state.log_event(self.name, "start_open_redirect_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_redirect_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "open_redirect_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_redirect_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff enforcing redirect URL validation."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -108,4 +108,8 @@\n"
            f" def handle_redirect():\n"
            f"     target = request.args.get('next', '/')\n"
            f"-    return redirect(target)\n"
            f"+    from urllib.parse import urlparse\n"
            f"+    parsed = urlparse(target)\n"
            f"+    if parsed.netloc and parsed.netloc not in ['corp.internal', 'app.internal']:\n"
            f"+        target = '/'\n"
            f"+    return redirect(target)"
        )
        explanation = (
            f"Open Redirect Remediation: Addressed {rule_id} (CWE-601) by introducing netloc domain validation "
            "using `urllib.parse.urlparse`. Unapproved external destinations are forced to default to safe internal root (`/`), "
            "neutralizing phishing vectors."
        )
        return diff, explanation
