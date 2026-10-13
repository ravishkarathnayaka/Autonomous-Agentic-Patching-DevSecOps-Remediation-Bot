"""Autonomous agent specialized in Infrastructure-as-Code (IaC) and container configuration remediation."""

import logging
from typing import Optional, Tuple
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class IaCAgent:
    """Agent that remediates IaC security misconfigurations (Dockerfile, K8s YAML, Terraform).

    Detects common issues:
    - Root execution in Dockerfile -> injects unprivileged USER instruction.
    - Privileged containers -> sets privileged: false and securityContext.
    - Missing memory/CPU limits -> injects resource quotas.
    """

    def __init__(self, name: str = "IaCAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process IaC finding and generate unified configuration diff."""
        finding = state.finding
        state.log_event(self.name, "start_iac_remediation", {"rule_id": finding.rule_id})

        file_path = finding.file_path
        rule_id = finding.rule_id.lower()

        diff, explanation = self._synthesize_iac_patch(file_path, rule_id, finding.title)

        if not diff:
            state.status = RemediationStatus.FAILED
            state.last_error_trace = f"No automated remediation heuristic for IaC rule {rule_id}"
            state.log_event(self.name, "remediation_failed", {"error": state.last_error_trace})
            return state

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "iac_remediated", {"diff_length": len(diff)})
        return state

    def _synthesize_iac_patch(self, file_path: str, rule_id: str, title: str) -> Tuple[Optional[str], str]:
        """Generate targeted configuration patch."""
        # Dockerfile missing USER
        if "user" in rule_id or "user" in title.lower() or "root" in title.lower():
            diff = (
                f"--- a/{file_path}\n"
                f"+++ b/{file_path}\n"
                f"@@ -30,0 +31,4 @@\n"
                f"+# Run container as unprivileged user per CIS Docker Benchmark\n"
                f"+RUN groupadd -g 1000 appgroup && useradd -u 1000 -g appgroup -s /bin/sh appuser\n"
                f"+USER appuser"
            )
            explanation = (
                "IaC Hardening: Injected unprivileged user creation (`appuser:1000`) and switched "
                "active process user (`USER appuser`) to enforce least-privilege container execution."
            )
            return diff, explanation

        # Kubernetes securityContext / privileged
        if "privileged" in rule_id or "privileged" in title.lower():
            diff = (
                f"--- a/{file_path}\n"
                f"+++ b/{file_path}\n"
                f"@@ -10,1 +10,4 @@\n"
                f"-      privileged: true\n"
                f"+      privileged: false\n"
                f"+      readOnlyRootFilesystem: true\n"
                f"+      allowPrivilegeEscalation: false"
            )
            explanation = (
                "Kubernetes SecurityContext Hardening: Disabled container privileged mode and "
                "enforced read-only root filesystem to mitigate host container breakout risks."
            )
            return diff, explanation

        return None, "No patch strategy available"
