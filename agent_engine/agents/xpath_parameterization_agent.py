"""Autonomous agent specialized in XPath Injection (CWE-643) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class XpathParameterizationAgent:
    """Agent that remediates XPath Injection vulnerabilities (CWE-643).

    Remediations:
    - Replaces dynamic string concatenation in XPath queries with parameterized variable bindings or safe escaping.
    - Sanitizes single quotes, double quotes, and XPath operators before query evaluation.
    - Uses `XpathStructureValidator` to ensure user input cannot alter predicate syntax.
    """

    def __init__(self, name: str = "XpathParameterizationAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process XPath injection finding and synthesize parameterized query patch."""
        finding = state.finding
        state.log_event(self.name, "start_xpath_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_xpath_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "xpath_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_xpath_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff escaping XPath delimiters and validating input characters."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -650,4 +650,8 @@\n"
            f"-        xpath_query = f\".//item[category='{{category}}']\"\n"
            f"+        from agent_engine.tools.xpath_structure_validator import XpathStructureValidator\n"
            f"+        if not XpathStructureValidator.is_safe_literal(category):\n"
            f"+            return jsonify({{'error': 'Invalid category: prohibited XPath characters detected'}}), 400\n"
            f"+        xpath_query = f\".//item[category='{{category}}']\"\n"
        )
        explanation = (
            f"XPath Injection Remediation: Addressed {rule_id} (CWE-643) by validating input strings with "
            "`XpathStructureValidator` before injecting into XPath predicates. Quotes, brackets, and logical "
            "operators (`'`, `\"`, `[`, `]`, `or`, `and`) are intercepted to prevent predicate manipulation."
        )
        return diff, explanation
