from pathlib import Path
from agent_engine.tools.defender_devops_parser import parse_defender_devops_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_defender_devops_report():
    fixture_path = Path(__file__).parent / "fixtures" / "defender_devops_findings.json"
    findings = parse_defender_devops_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "defender-devops"
    assert f.finding_type == FindingType.SAST
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "MS_DevOps_SQL_Injection"
    assert "CWE-89" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 38
