from pathlib import Path
from agent_engine.tools.clang_tidy_parser import parse_clang_tidy_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_clang_tidy_report():
    fixture_path = Path(__file__).parent / "fixtures" / "clang_tidy_findings.json"
    findings = parse_clang_tidy_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "clang-tidy"
    assert f.finding_type == FindingType.SAST
    assert f.rule_id == "cert-err34-c"
    assert f.severity == SeverityLevel.HIGH
    assert f.file_path == "src/parser.c"
    assert "atoi" in f.description
