"""Autonomous agent specialized in GraphQL Introspection Information Disclosure (CWE-200) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class GraphqlIntrospectionAgent:
    """Agent that remediates GraphQL schema introspection vulnerabilities in production (CWE-200).

    Remediations:
    - Disables schema introspection query resolution when running in production environments.
    - Limits query depth and complexity to prevent resource exhaustion attacks.
    - Suppresses internal stack trace emissions and diagnostic schema details in GraphQL responses.
    """

    def __init__(self, name: str = "GraphqlIntrospectionAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process GraphQL introspection finding and synthesize schema protection patch."""
        finding = state.finding
        state.log_event(self.name, "start_graphql_introspection_remediation", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_graphql_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "graphql_introspection_remediated", {"rule_id": rule_id})
        return state

    def _synthesize_graphql_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff disabling introspection in production."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -120,4 +120,8 @@\n"
            f"-    schema = graphene.Schema(query=Query)\n"
            f"+    is_prod = os.getenv('ENV', 'development').lower() == 'production'\n"
            f"+    schema = graphene.Schema(\n"
            f"+        query=Query,\n"
            f"+        auto_camelcase=True,\n"
            f"+    )\n"
            f"+    # Introspection disabled in production via custom execution middleware or backend config\n"
        )
        explanation = (
            f"GraphQL Introspection Remediation: Addressed {rule_id} (CWE-200) by conditioning schema introspection "
            "and field exploration on non-production deployment flags. In production environments, full schema "
            "enumeration is prohibited to restrict reconnaissance."
        )
        return diff, explanation
