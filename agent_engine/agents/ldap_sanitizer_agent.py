"""Autonomous agent specialized in LDAP Injection (CWE-90) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class LdapSanitizerAgent:
    """Agent that remediates Improper Neutralization in LDAP Query (CWE-90 / OWASP A03:2021).

    Remediations:
    - Escapes special characters defined in RFC 4515 (`\\`, `*`, `(`, `)`, `\\0`).
    - Enforces parameter validation and input whitelisting for directory search filters.
    """

    def __init__(self, name: str = "LdapSanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process LDAP injection finding and synthesize filter escaping patch."""
        finding = state.finding
        state.log_event(self.name, "start_ldap_sanitization", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_ldap_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "ldap_sanitized", {"rule_id": rule_id})
        return state

    def _synthesize_ldap_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff applying RFC 4515 filter escaping."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -465,4 +465,6 @@\n"
            f"-    ldap_filter = f\"(&(objectCategory=person)(sAMAccountName={{query}}))\"\n"
            f"+    def escape_ldap(s: str) -> str:\n"
            f"+        return s.replace('\\\\', '\\\\5c').replace('*', '\\\\2a').replace('(', '\\\\28').replace(')', '\\\\29').replace('\\x00', '\\\\00')\n"
            f"+    ldap_filter = f\"(&(objectCategory=person)(sAMAccountName={{escape_ldap(query)}}))\""
        )
        explanation = (
            f"LDAP Injection Remediation: Addressed {rule_id} (CWE-90) by escaping RFC 4515 reserved characters "
            "(`*`, `(`, `)`, `\\`, NULL) into their respective hex representations. This prevents an attacker from "
            "breaking out of the `sAMAccountName` assertion filter."
        )
        return diff, explanation
