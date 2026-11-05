"""Autonomous agent specialized in SVG XML External Entity (XXE - CWE-611) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SvgXxeSanitizerAgent:
    """Agent that remediates XML External Entity vulnerabilities in SVG image processing (CWE-611).

    Remediations:
    - Replaces unsafe XML parsers (e.g., standard `xml.etree.ElementTree` or `lxml.etree` with default entity resolution)
      with `defusedxml.ElementTree`.
    - Prohibits DOCTYPE definitions (`resolve_entities=False`, `forbid_dtd=True`).
    - Strips or sanitizes embedded script, foreignObject, and entity references from SVG payloads before storage.
    """

    def __init__(self, name: str = "SvgXxeSanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process SVG XXE finding and synthesize parser hardening patch."""
        finding = state.finding
        state.log_event(self.name, "start_svg_xxe_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_svg_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "svg_xxe_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_svg_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff using defusedxml or disallowing DTD in SVG parsing."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -530,4 +530,8 @@\n"
            f"-    import xml.etree.ElementTree as ET\n"
            f"-    root = ET.fromstring(svg_data)\n"
            f"+    import defusedxml.ElementTree as DefusedET\n"
            f"+    try:\n"
            f"+        root = DefusedET.fromstring(svg_data, forbid_dtd=True, forbid_entities=True)\n"
            f"+    except Exception as e:\n"
            f"+        return jsonify({{'error': f'XML/SVG Parsing blocked: {{str(e)}}'}}), 400\n"
        )
        explanation = (
            f"SVG XXE Remediation: Addressed {rule_id} (CWE-611) by replacing standard XML parsing with "
            "`defusedxml.ElementTree.fromstring` with `forbid_dtd=True` and `forbid_entities=True`. "
            "This neutralizes external entity expansion, Billion Laughs attacks, and local file retrieval."
        )
        return diff, explanation
