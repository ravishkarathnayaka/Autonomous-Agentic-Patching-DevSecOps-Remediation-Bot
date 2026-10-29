from pathlib import Path
from agent_engine.tools.spotbugs_parser import parse_spotbugs_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_spotbugs_report():
    fixture_path = Path(__file__).parent / "fixtures" / "spotbugs_findings.json"
    findings = parse_spotbugs_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "spotbugs"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "SQL_INJECTION_JDBC"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-89" in f.cwe_ids
    assert f.file_path == "src/main/java/com/example/UserService.java"
    assert f.start_line == 58
