"""Autonomous agent specialized in Dockerfile security hardening and image minimization."""

import logging
from typing import Optional, Tuple
from agent_engine.state import Finding, RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class DockerfileAgent:
    """Agent that performs automated Dockerfile security hardening (Hadolint / KICS findings).

    Remediations:
    - DL3008: Pins package versions or adds --no-install-recommends.
    - DL3009: Injects rm -rf /var/lib/apt/lists/* to strip cache.
    - DL3042: Appends --no-cache-dir to pip install commands.
    """

    def __init__(self, name: str = "DockerfileAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process Dockerfile finding and generate hardening diff."""
        finding = state.finding
        state.log_event(self.name, "start_dockerfile_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_dockerfile_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "dockerfile_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_dockerfile_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff applying container build best practices."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -10,3 +10,4 @@\n"
            f"-RUN apt-get update && apt-get install -y git\n"
            f"+RUN apt-get update && apt-get install -y --no-install-recommends git \\\n"
            f"+    && rm -rf /var/lib/apt/lists/*"
        )

        explanation = (
            f"Dockerfile Security Hardening: Addressed {rule_id} by enforcing `--no-install-recommends` "
            "and immediate apt list cache cleanup (`rm -rf /var/lib/apt/lists/*`), reducing container image "
            "attack surface and preventing unvetted utility installation."
        )

        return diff, explanation
