from agent_engine.agents.graphql_sanitizer_agent import GraphQLSanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_graphql_introspection_disabled():
    finding = Finding(
        id="semgrep-graphql-introspection-enabled",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="graphql.introspection.enabled",
        title="GraphQL introspection enabled in production",
        description="Publicly reveals entire backend GraphQL schema",
        severity=SeverityLevel.HIGH,
        file_path="api/graphql.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = GraphQLSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "introspection=os.getenv('ENV') == 'development'" in updated.patch_diff
    assert "OWASP API8:2023" in updated.patch_explanation


def test_graphql_depth_limiting():
    finding = Finding(
        id="semgrep-graphql-unlimited-depth",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="graphql.dos.unlimited-query-depth",
        title="GraphQL query depth unlimited",
        description="Vulnerable to circular nested query DoS",
        severity=SeverityLevel.MEDIUM,
        file_path="api/schema.py"
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = GraphQLSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "depth_limit_validator(max_depth=6)" in updated.patch_diff
    assert "circular query expansion" in updated.patch_explanation
