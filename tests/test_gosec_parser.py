from pathlib import Path
from agent_engine.tools.gosec_parser import parse_gosec_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_gosec_report():
    fixture_path = Path(__file__).parent / "fixtures" / "gosec_findings.json"
    findings = parse_gosec_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "gosec"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "G201"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-89" in f.cwe_ids
    assert f.file_path == "server/db.go"
    assert "fmt.Sprintf" in f.vulnerable_code
