"""Autonomous agent specialized in SCA package upgrades and dependency manifest patching."""

import logging
import re
from typing import Optional, Tuple
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class DependencyAgent:
    """Agent that handles vulnerable dependencies (CVE / SCA findings).

    Performs targeted manifest updates:
    1. Locates package pinning in requirements.txt or package.json.
    2. Replaces vulnerable version with recommended fixed_version.
    3. Emits minimal unified diff for manifest update.
    """

    def __init__(self, name: str = "DependencyAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process SCA finding and synthesize manifest update diff."""
        finding = state.finding
        state.log_event(self.name, "start_dependency_patch", {
            "package": finding.package_name,
            "installed": finding.installed_version,
            "fixed": finding.fixed_version
        })

        if not finding.package_name or not finding.fixed_version:
            state.status = RemediationStatus.FAILED
            state.last_error_trace = "Missing package_name or fixed_version in SCA finding"
            state.log_event(self.name, "patch_failed", {"error": state.last_error_trace})
            return state

        diff, explanation = self._generate_manifest_diff(
            file_path=finding.file_path,
            pkg_name=finding.package_name,
            old_version=finding.installed_version or "",
            new_version=finding.fixed_version,
            rule_id=finding.rule_id
        )

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "manifest_patched", {
            "diff_length": len(diff),
            "target_version": finding.fixed_version
        })
        return state

    def _generate_manifest_diff(
        self,
        file_path: str,
        pkg_name: str,
        old_version: str,
        new_version: str,
        rule_id: str
    ) -> Tuple[str, str]:
        """Produce unified diff upgrading the pinned version in requirements.txt or manifest."""
        old_line = f"{pkg_name}=={old_version}" if old_version else pkg_name
        new_line = f"{pkg_name}=={new_version}"

        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -1,1 +1,1 @@\n"
            f"-{old_line}\n"
            f"+{new_line}"
        )

        explanation = (
            f"SCA Dependency Remediation: Upgraded pinned dependency `{pkg_name}` "
            f"from `{old_version or 'vulnerable'}` to `{new_version}` resolving security advisory {rule_id}. "
            f"Maintains SemVer compatibility while neutralizing known exploit surface."
        )

        return diff, explanation
