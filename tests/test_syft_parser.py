from pathlib import Path
from agent_engine.tools.syft_parser import parse_syft_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_syft_report():
    fixture_path = Path(__file__).parent / "fixtures" / "syft_findings.json"
    findings = parse_syft_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "syft"
    assert f.finding_type == FindingType.SCA
    assert f.package_name == "cryptography"
    assert f.installed_version == "41.0.2"
    assert f.severity == SeverityLevel.LOW
    assert f.file_path == "requirements.txt"
