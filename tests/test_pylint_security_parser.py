from pathlib import Path
from agent_engine.tools.pylint_security_parser import parse_pylint_security_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_pylint_security_report():
    fixture_path = Path(__file__).parent / "fixtures" / "pylint_security_findings.json"
    findings = parse_pylint_security_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "pylint-security"
    assert f.finding_type == FindingType.SAST
    assert f.severity == SeverityLevel.HIGH
    assert f.rule_id == "pylint.eval-used"
    assert "CWE-95" in f.cwe_ids
    assert f.file_path == "target_repo/app.py"
    assert f.start_line == 245
