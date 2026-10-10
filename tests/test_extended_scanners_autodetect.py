from pathlib import Path
import pytest
from agent_engine.tools.report_parsers import load_findings_from_file


def test_autodetect_all_new_scanners():
    fixtures_dir = Path(__file__).parent / "fixtures"

    zap_findings = load_findings_from_file(fixtures_dir / "zap_findings.json")
    assert len(zap_findings) == 2
    assert zap_findings[0].scanner == "owasp_zap"

    kics_findings = load_findings_from_file(fixtures_dir / "kics_findings.json")
    assert len(kics_findings) == 2
    assert kics_findings[0].scanner == "kics"

    grype_findings = load_findings_from_file(fixtures_dir / "grype_findings.json")
    assert len(grype_findings) == 1
    assert grype_findings[0].scanner == "grype"

    trufflehog_findings = load_findings_from_file(fixtures_dir / "trufflehog_findings.json")
    assert len(trufflehog_findings) == 2
    assert trufflehog_findings[0].scanner == "trufflehog"

    horusec_findings = load_findings_from_file(fixtures_dir / "horusec_findings.json")
    assert len(horusec_findings) == 2
    assert horusec_findings[0].scanner == "horusec"
