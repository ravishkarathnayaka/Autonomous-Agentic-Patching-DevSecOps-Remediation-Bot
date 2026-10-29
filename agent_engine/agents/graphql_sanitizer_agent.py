"""Autonomous agent specialized in GraphQL API security hardening and DoS prevention."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class GraphQLSanitizerAgent:
    """Agent that remediates GraphQL security vulnerabilities (OWASP API Security Top 10).

    Remediations:
    - INTROSPECTION_ENABLED: Disables schema introspection in production environments.
    - QUERY_DEPTH_UNRESTRICTED: Adds recursive query depth limits to mitigate denial of service.
    """

    def __init__(self, name: str = "GraphQLSanitizerAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process GraphQL finding and generate security hardening patch."""
        finding = state.finding
        state.log_event(self.name, "start_graphql_sanitization", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_graphql_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "graphql_sanitized", {"rule_id": rule_id})
        return state

    def _synthesize_graphql_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff applying GraphQL defense-in-depth controls."""
        if "INTROSPECTION" in rule_id:
            diff = (
                f"--- a/{file_path}\n"
                f"+++ b/{file_path}\n"
                f"@@ -12,4 +12,6 @@\n"
                f" schema = graphene.Schema(\n"
                f"     query=Query,\n"
                f"-    mutation=Mutation\n"
                f"+    mutation=Mutation,\n"
                f"+    auto_camelcase=True\n"
                f"+)\n"
                f"+# In production, disable schema introspection (CWE-200)\n"
                f"+view = GraphQLView.as_view(schema=schema, introspection=os.getenv('ENV') == 'development')"
            )
            explanation = (
                f"GraphQL Remediation: Disabled public schema introspection for {file_path} in production, "
                "preventing schema reconnaissance and endpoint enumeration per OWASP API8:2023."
            )
        else:
            diff = (
                f"--- a/{file_path}\n"
                f"+++ b/{file_path}\n"
                f"@@ -8,3 +8,6 @@\n"
                f" from graphql import validate\n"
                f"+from graphql_depth_limit import depth_limit_validator\n"
                f" \n"
                f"-validation_rules = []\n"
                f"+# Prevent exponential nested query DoS (CWE-770)\n"
                f"+validation_rules = [depth_limit_validator(max_depth=6)]"
            )
            explanation = (
                f"GraphQL Remediation: Enforced maximum query depth limit of 6 on {file_path}, "
                "defending backend services against circular query expansion and resource exhaustion DoS."
            )

        return diff, explanation
