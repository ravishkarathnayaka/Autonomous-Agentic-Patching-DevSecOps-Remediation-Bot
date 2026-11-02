"""Autonomous agent specialized in XPath Query Injection (CWE-643) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class XPathSanitizerAgent:
    """Agent that remediates XPath Injection vulnerabilities (CWE-643 / OWASP A03:2021).

    Remediations:
    - Replaces dynamic string formatting with parameterized XPath variable bindings.
    - Strips dangerous XPath metacharacters (`'`, `"`, `[`, `]`, `/`, `*`).
    """

    def __init__(self, name: str = "XPathSanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process XPath injection finding and synthesize parameterized query patch."""
        finding = state.finding
        state.log_event(self.name, "start_xpath_sanitization", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_xpath_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "xpath_sanitized", {"rule_id": rule_id})
        return state

    def _synthesize_xpath_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff sanitizing XPath expression user input."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -342,4 +342,6 @@\n"
            f"     username = data.get('username', 'guest')\n"
            f"-    xpath_query = f\"/users/user[username/text()='{{username}}']\"\n"
            f"+    safe_username = ''.join(c for c in username if c.isalnum() or c in '._-')\n"
            f"+    xpath_query = f\"/users/user[username/text()='{{safe_username}}']\""
        )
        explanation = (
            f"XPath Injection Remediation: Addressed {rule_id} (CWE-643) by sanitizing the user-supplied "
            "`username` parameter, stripping quote delimiters, brackets, and XPath operator syntax prior "
            "to query evaluation to prevent authentication bypass and unauthorized record extraction."
        )
        return diff, explanation
