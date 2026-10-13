from pathlib import Path
from agent_engine.tools.eslint_security_parser import parse_eslint_security_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_eslint_security_report_fixture():
    fixture_path = Path("tests/fixtures/eslint_security_findings.json")
    findings = parse_eslint_security_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "eslint-security"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "security/detect-eval-with-expression"
    assert f.severity == SeverityLevel.HIGH
    assert "CWE-95" in f.cwe_ids
    assert f.file_path == "web/src/utils/evaluator.ts"
    assert f.start_line == 42


def test_parse_eslint_empty():
    assert parse_eslint_security_report([]) == []
