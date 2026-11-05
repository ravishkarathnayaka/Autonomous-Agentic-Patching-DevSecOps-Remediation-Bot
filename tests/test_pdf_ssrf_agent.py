from agent_engine.agents.pdf_ssrf_agent import PdfSsrfSanitizerAgent
from agent_engine.state import Finding, FindingType, RemediationState, RemediationStatus, SeverityLevel


def test_pdf_ssrf_agent_remediation():
    finding = Finding(
        id="stackhawk-pdf-ssrf-01",
        scanner="stackhawk",
        finding_type=FindingType.DAST,
        rule_id="CWE-918",
        title="Server-Side Request Forgery via PDF Renderer",
        description="Arbitrary URL input directly supplied to HTML-to-PDF conversion service",
        severity=SeverityLevel.HIGH,
        cwe_ids=["CWE-918"],
        file_path="target_repo/app.py",
    )

    state = RemediationState(finding=finding, target_repo_path=".")
    agent = PdfSsrfSanitizerAgent()
    updated = agent.execute(state)

    assert updated.status == RemediationStatus.PATCH_GENERATED
    assert "PdfUriAllowlistValidator" in updated.patch_diff
    assert "Disallowed target URL" in updated.patch_diff
    assert "CWE-918" in updated.patch_explanation
