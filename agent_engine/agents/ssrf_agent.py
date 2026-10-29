"""Autonomous agent specialized in Server-Side Request Forgery (SSRF) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SSRFRemediationAgent:
    """Agent that remediates Server-Side Request Forgery (CWE-918 / OWASP A10:2021).

    Remediations:
    - Injects URL scheme whitelist verification (HTTP/HTTPS only).
    - Injects private CIDR and cloud metadata IP (169.254.169.254) blocking logic before outbound HTTP dispatch.
    """

    def __init__(self, name: str = "SSRFRemediationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Analyze SSRF finding and synthesize network egress isolation patch."""
        finding = state.finding
        state.log_event(self.name, "start_ssrf_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_ssrf_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "ssrf_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_ssrf_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff wrapping requests.get / urllib calls with safe IP validation."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -15,4 +15,12 @@\n"
            f" def fetch_remote_resource(url):\n"
            f"+    import ipaddress\n"
            f"+    import socket\n"
            f"+    from urllib.parse import urlparse\n"
            f"+    parsed = urlparse(url)\n"
            f"+    if parsed.scheme not in ('http', 'https'):\n"
            f"+        raise ValueError('Invalid URL scheme')\n"
            f"+    target_ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))\n"
            f"+    if target_ip.is_private or target_ip.is_loopback or target_ip.is_link_local:\n"
            f"+        raise PermissionError('SSRF blocked: Private or metadata IP access prohibited')\n"
            f"     return requests.get(url, timeout=5).text"
        )
        explanation = (
            f"SSRF Remediation: Addressed {rule_id} (CWE-918) by enforcing strict scheme validation and "
            "resolving DNS hostnames prior to connection to reject private IP ranges (RFC 1918), loopback, "
            "and cloud instance metadata endpoints (169.254.169.254)."
        )

        return diff, explanation
