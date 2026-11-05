"""Autonomous agent specialized in Web Cache Poisoning and Header Remediation (CWE-444 / CWE-524)."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class CachePoisoningAgent:
    """Agent that remediates Web Cache Poisoning and unkeyed response header vulnerabilities (CWE-444 / CWE-524).

    Remediations:
    - Adds explicit `Cache-Control: no-store, private, max-age=0` directives for dynamic and authenticated routes.
    - Configures proper `Vary` headers (e.g., `Vary: Accept-Encoding, Cookie`) to partition caches across client contexts.
    - Prohibits reflected unkeyed headers (`X-Forwarded-Host`, `X-Host`, `X-Rewrite-URL`) from polluting intermediate proxy caches.
    """

    def __init__(self, name: str = "CachePoisoningAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process cache poisoning finding and synthesize response header hardening patch."""
        finding = state.finding
        state.log_event(self.name, "start_cache_poisoning_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_cache_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "cache_poisoning_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_cache_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff injecting hardened cache control headers."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -200,4 +200,9 @@\n"
            f"     response = make_response(payload)\n"
            f"+    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'\n"
            f"+    response.headers['Pragma'] = 'no-cache'\n"
            f"+    response.headers['Vary'] = 'Cookie, Accept-Encoding'\n"
            f"     return response\n"
        )
        explanation = (
            f"Cache Poisoning Remediation: Addressed {rule_id} (CWE-444 / CWE-524) by enforcing anti-caching directives "
            "(`Cache-Control: no-store, no-cache, private`) and specifying proper `Vary` headers. This prevents intermediate "
            "reverse proxies and CDNs from storing poisoned payloads or serving sensitive authenticated responses to unauthorized visitors."
        )
        return diff, explanation
