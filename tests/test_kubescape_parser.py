from pathlib import Path
from agent_engine.tools.kubescape_parser import parse_kubescape_report
from agent_engine.state import FindingType, SeverityLevel


def test_parse_kubescape_report():
    fixture_path = Path(__file__).parent / "fixtures" / "kubescape_findings.json"
    findings = parse_kubescape_report(fixture_path)

    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "kubescape"
    assert f.finding_type == FindingType.IAC
    assert f.rule_id == "C-0046"
    assert f.severity == SeverityLevel.CRITICAL
    assert f.file_path == "deploy/k8s.yaml"
    assert "docker.sock" in f.vulnerable_code
