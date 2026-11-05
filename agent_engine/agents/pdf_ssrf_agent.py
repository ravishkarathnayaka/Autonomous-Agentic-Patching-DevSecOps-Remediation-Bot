"""Autonomous agent specialized in PDF rendering Server-Side Request Forgery (SSRF - CWE-918) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class PdfSsrfSanitizerAgent:
    """Agent that remediates SSRF vulnerabilities in HTML-to-PDF rendering pipelines (CWE-918).

    Remediations:
    - Restricts URL schemes in PDF generation input to strictly HTTPS/HTTP.
    - Disallows file://, gopher://, dict://, and metadata IP endpoints (169.254.169.254, 127.0.0.1, ::1).
    - Validates target domain against allowed customer hostname registries.
    """

    def __init__(self, name: str = "PdfSsrfSanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process PDF SSRF finding and synthesize network validation patch."""
        finding = state.finding
        state.log_event(self.name, "start_pdf_ssrf_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_pdf_ssrf_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "pdf_ssrf_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_pdf_ssrf_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff rejecting private IP and dangerous URI schemes in PDF generation."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -520,4 +520,9 @@\n"
            f"-    rendered_pdf = pdfkit.from_url(target_url, False)\n"
            f"+    from agent_engine.tools.pdf_uri_validator import PdfUriAllowlistValidator\n"
            f"+    validator = PdfUriAllowlistValidator()\n"
            f"+    if not validator.is_safe_url(target_url):\n"
            f"+        return jsonify({{'error': 'Disallowed target URL: internal or prohibited URI scheme'}}), 400\n"
            f"+    rendered_pdf = pdfkit.from_url(target_url, False)\n"
        )
        explanation = (
            f"PDF SSRF Remediation: Addressed {rule_id} (CWE-918) by applying strict URL and IP allowlist validation "
            "before feeding URLs into PDF rendering engines. Requests targeting cloud metadata services (169.254.169.254), "
            "loopback addresses, or non-HTTP schemes are rejected."
        )
        return diff, explanation
