from pathlib import Path
import pytest
from agent_engine.state import FindingType, SeverityLevel
from agent_engine.tools.bearer_parser import parse_bearer_report


def test_parse_bearer_report():
    fixture_path = Path("tests/fixtures/bearer_findings.json")
    findings = parse_bearer_report(fixture_path)

    assert len(findings) == 2

    f1 = findings[0]
    assert f1.scanner == "bearer"
    assert f1.finding_type == FindingType.SAST
    assert f1.rule_id == "python_lang_sql_injection"
    assert f1.severity == SeverityLevel.CRITICAL
    assert f1.file_path == "target_repo/app.py"
    assert f1.start_line == 68
    assert "CWE-89" in f1.cwe_ids

    f2 = findings[1]
    assert f2.rule_id == "python_lang_ssrf"
    assert f2.severity == SeverityLevel.HIGH
    assert f2.start_line == 372
    assert "CWE-918" in f2.cwe_ids
