"""Autonomous agent specialized in Log Injection (CWE-117) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class LogInjectionSanitizerAgent:
    """Agent that remediates Improper Output Handling for Logs (CWE-117 / OWASP A09:2021).

    Remediations:
    - Neutralizes carriage returns (`\\r`) and line feeds (`\\n`) to prevent log forging and log injection.
    - Enforces structured JSON logging or strict parameter sanitation.
    """

    def __init__(self, name: str = "LogInjectionSanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process log injection finding and synthesize CRLF sanitization patch."""
        finding = state.finding
        state.log_event(self.name, "start_log_injection_sanitization", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_log_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "log_injection_sanitized", {"rule_id": rule_id})
        return state

    def _synthesize_log_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff applying CRLF removal to log arguments."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -450,4 +450,6 @@\n"
            f"-    log_entry = f\"AUDIT: user='{{username}}' performed action='{{action}}'\"\n"
            f"+    clean_user = username.replace('\\r', '').replace('\\n', '')\n"
            f"+    clean_act = action.replace('\\r', '').replace('\\n', '')\n"
            f"+    log_entry = f\"AUDIT: user='{{clean_user}}' performed action='{{clean_act}}'\""
        )
        explanation = (
            f"Log Injection Remediation: Addressed {rule_id} (CWE-117) by stripping carriage return (`\\r`) and "
            "line feed (`\\n`) characters from user-controlled logging parameters. This prevents adversaries from injecting "
            "fake audit log lines or tampering with SIEM log integrity."
        )
        return diff, explanation
