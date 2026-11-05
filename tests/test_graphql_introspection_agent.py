from agent_engine.agents.graphql_introspection_agent import GraphqlIntrospectionAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_graphql_introspection_agent_remediation():
    finding = Finding(
        id="stackhawk-graphql-intro-01",
        scanner="stackhawk",
        finding_type=FindingType.DAST,
        rule_id="CWE-200",
        title="GraphQL Introspection Enabled in Production",
        description="Production GraphQL schema exposes full field schema and internal mutations",
        severity=SeverityLevel.MEDIUM,
        cwe_ids=["CWE-200"],
        file_path="target_repo/graphql_api.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = GraphqlIntrospectionAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "is_prod" in updated.patch_diff
    assert "Introspection disabled" in updated.patch_diff
    assert "CWE-200" in updated.patch_explanation
