from agent_engine.agents.svg_xxe_agent import SvgXxeSanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_svg_xxe_agent_remediation():
    finding = Finding(
        id="semgrep-svg-xxe-01",
        scanner="semgrep",
        finding_type=FindingType.SAST,
        rule_id="CWE-611",
        title="Improper Restriction of XML External Entity Reference in SVG Upload",
        description="Parsing untrusted SVG files without disabling entity resolution",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-611"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = SvgXxeSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "defusedxml.ElementTree" in updated.patch_diff
    assert "forbid_dtd=True" in updated.patch_diff
    assert "CWE-611" in updated.patch_explanation
