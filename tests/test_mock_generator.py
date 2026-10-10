from pathlib import Path
from scripts.generate_mock_scans import generate_all_mock_reports
from agent_engine.tools.report_parsers import load_findings_from_file


def test_generate_mock_reports(tmp_path: Path):
    created = generate_all_mock_reports(tmp_path)
    assert len(created) >= 3
    assert "semgrep" in created
    assert "trivy" in created
    assert "gitleaks" in created

    # Verify that generated files can be parsed by engine
    semgrep_findings = load_findings_from_file(created["semgrep"])
    assert len(semgrep_findings) == 1
    assert semgrep_findings[0].scanner == "semgrep"

    trivy_findings = load_findings_from_file(created["trivy"])
    assert len(trivy_findings) == 1
    assert trivy_findings[0].scanner == "trivy"
