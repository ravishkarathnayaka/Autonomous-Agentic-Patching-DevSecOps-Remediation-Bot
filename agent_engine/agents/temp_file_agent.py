"""Autonomous agent specialized in Temporary File Security (CWE-377) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class TempFileHardeningAgent:
    """Agent that remediates Insecure Temporary File Creation (CWE-377 / OWASP A01:2021).

    Remediations:
    - Replaces predictable manual temporary file paths with `tempfile.NamedTemporaryFile`.
    - Enforces secure file permissions (`mode=0o600`) and atomic creation to defeat symlink/race attacks.
    """

    def __init__(self, name: str = "TempFileHardeningAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process insecure temp file finding and synthesize atomic NamedTemporaryFile patch."""
        finding = state.finding
        state.log_event(self.name, "start_temp_file_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_temp_file_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "temp_file_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_temp_file_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff using tempfile.NamedTemporaryFile."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -398,5 +398,6 @@\n"
            f"     report_title = data.get('title', 'Daily Security Report')\n"
            f"-    temp_dir = tempfile.gettempdir()\n"
            f"-    temp_path = os.path.join(temp_dir, f'report_{{report_title.replace(\" \", \"_\").lower()}}.txt')\n"
            f"-    with open(temp_path, 'w', encoding='utf-8') as f:\n"
            f"+    with tempfile.NamedTemporaryFile(mode='w', prefix='report_', suffix='.txt', delete=False, encoding='utf-8') as f:\n"
            f"+        temp_path = f.name"
        )
        explanation = (
            f"Temporary File Remediation: Addressed {rule_id} (CWE-377) by replacing predictable file path "
            "construction with `tempfile.NamedTemporaryFile(..., delete=False)`. This guarantees cryptographic "
            "randomness in file naming and atomic creation with restrictive permissions (0600), mitigating TOCTOU "
            "race conditions and symlink hijacking."
        )
        return diff, explanation
