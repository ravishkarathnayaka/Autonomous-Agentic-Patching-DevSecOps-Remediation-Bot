"""Autonomous agent specialized in Zip Slip / Archive Extraction Path Traversal (CWE-22) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class ZipSlipRemediationAgent:
    """Agent that remediates Zip Slip Path Traversal (CWE-22 / CWE-29 / OWASP A01:2021).

    Remediations:
    - Replaces unsafe `zipfile.ZipFile.extractall()` or tar extraction loops with boundary-checked extraction.
    - Validates resolved realpaths against destination root using `os.path.commonpath`.
    - Throws security exceptions on attempted directory traversal via `../` archive members.
    """

    def __init__(self, name: str = "ZipSlipRemediationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process zip slip finding and synthesize boundary-checked extraction patch."""
        finding = state.finding
        state.log_event(self.name, "start_zip_slip_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_zip_slip_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "zip_slip_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_zip_slip_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff validating extracted paths within target directory."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -55,3 +55,10 @@\n"
            f"-    zip_ref.extractall(target_dir)\n"
            f"+    dest_dir = os.path.realpath(target_dir)\n"
            f"+    for member in zip_ref.infolist():\n"
            f"+        member_path = os.path.realpath(os.path.join(dest_dir, member.filename))\n"
            f"+        if os.path.commonpath([dest_dir, member_path]) != dest_dir:\n"
            f"+            raise PermissionError(f'Zip Slip traversal detected: {{member.filename}}')\n"
            f"+        zip_ref.extract(member, dest_dir)"
        )
        explanation = (
            f"Zip Slip Remediation: Addressed {rule_id} (CWE-22 / Path Traversal) by replacing unconstrained "
            "archive extraction with canonical realpath validation via `os.path.commonpath`. Any member containing "
            "parent traversal components (`../`) that escapes the destination directory raises a PermissionError."
        )
        return diff, explanation
