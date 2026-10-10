import json
from pathlib import Path
from scripts.validate_sarif import validate_sarif_file
from agent_engine.tools.sarif_exporter import export_findings_to_sarif
from agent_engine.state import Finding, SeverityLevel


def test_validate_sarif_file(tmp_path: Path):
    f = Finding(
        id="f-val-1",
        scanner="semgrep",
        rule_id="CWE-89",
        title="SQLi",
        description="SQL injection",
        severity=SeverityLevel.HIGH,
        file_path="app.py"
    )
    sarif_file = tmp_path / "valid.sarif"
    export_findings_to_sarif([f], output_path=sarif_file)

    valid, errors = validate_sarif_file(sarif_file)
    assert valid is True
    assert len(errors) == 0


def test_validate_sarif_file_invalid(tmp_path: Path):
    bad_file = tmp_path / "bad.sarif"
    bad_file.write_text(json.dumps({"version": "1.0.0"}), encoding="utf-8")

    valid, errors = validate_sarif_file(bad_file)
    assert valid is False
    assert any("Expected SARIF version '2.1.0'" in e for e in errors)
