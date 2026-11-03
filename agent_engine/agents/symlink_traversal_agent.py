"""Autonomous agent specialized in Symlink Traversal (CWE-59 / CWE-22) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SymlinkTraversalAgent:
    """Agent that remediates Improper Link Resolution Before File Access (CWE-59 / CWE-22).

    Remediations:
    - Resolves canonical target paths using `os.path.realpath`.
    - Enforces boundary checking via `os.path.commonpath([base_dir, resolved_path]) == base_dir`.
    - Prohibits reading or writing through symbolic links pointing outside designated root.
    """

    def __init__(self, name: str = "SymlinkTraversalAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process symlink traversal finding and synthesize boundary validation patch."""
        finding = state.finding
        state.log_event(self.name, "start_symlink_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_symlink_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "symlink_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_symlink_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff verifying canonical paths and blocking symlink breakouts."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -498,4 +498,8 @@\n"
            f"-    target_path = os.path.join(SAFE_DIR, filename)\n"
            f"+    base_dir = os.path.realpath(SAFE_DIR)\n"
            f"+    target_path = os.path.realpath(os.path.join(base_dir, filename))\n"
            f"+    if os.path.commonpath([base_dir, target_path]) != base_dir:\n"
            f"+        return jsonify({{'error': 'Symlink traversal blocked'}}), 403\n"
            f"     try:\n"
            f"         with open(target_path, 'r', encoding='utf-8') as f:"
        )
        explanation = (
            f"Symlink Traversal Remediation: Addressed {rule_id} (CWE-59 / CWE-22) by canonicalizing "
            "file paths via `os.path.realpath` and verifying that the destination resides strictly inside "
            "`SAFE_DIR` via `os.path.commonpath`. Symlinks pointing to parent directories or sensitive files are blocked."
        )
        return diff, explanation
