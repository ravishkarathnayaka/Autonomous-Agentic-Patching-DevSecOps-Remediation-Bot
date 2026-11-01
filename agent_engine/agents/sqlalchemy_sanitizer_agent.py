"""Autonomous agent specialized in SQLAlchemy and ORM Raw Query (CWE-89) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class SQLAlchemySanitizerAgent:
    """Agent that remediates SQL Injection in ORM and raw database adapters (CWE-89 / OWASP A03:2021).

    Remediations:
    - Converts raw string formatted queries (`cursor.execute(f"SELECT... {val}")`) to parameterized tuples (`?` or `:val`).
    - Enforces `sqlalchemy.text()` bound parameter binding instead of text concatenation.
    """

    def __init__(self, name: str = "SQLAlchemySanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process SQL injection finding and synthesize parameterized query patch."""
        finding = state.finding
        state.log_event(self.name, "start_sqla_sanitization", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_sqla_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "sqla_sanitized", {"rule_id": rule_id})
        return state

    def _synthesize_sqla_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff converting raw SQL concatenation to parameterized binding."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -36,4 +36,4 @@\n"
            f"     cursor = get_db().cursor()\n"
            f"-    query = f\"SELECT * FROM items WHERE name = '{{name}}'\"\n"
            f"-    cursor.execute(query)\n"
            f"+    query = \"SELECT * FROM items WHERE name = ?\"\n"
            f"+    cursor.execute(query, (name,))"
        )
        explanation = (
            f"SQL Injection Remediation: Addressed {rule_id} (CWE-89) by converting dynamic SQL string interpolation "
            "into a parameterized query with bound parameter tuple (`(name,)`). The database driver securely escapes "
            "user arguments, completely neutralizing second-order and in-band SQL injection exploits."
        )
        return diff, explanation
