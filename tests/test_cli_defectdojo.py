import json
from click.testing import CliRunner
from cli.defectdojo_cli import defectdojo_finding


def test_cli_defectdojo_finding_stdout():
    runner = CliRunner()
    result = runner.invoke(
        defectdojo_finding,
        [
            "--test-id",
            "10",
            "--scanner",
            "codeql",
            "--rule-id",
            "CWE-89",
            "--title",
            "SQL Injection",
            "--severity",
            "CRITICAL",
            "--file",
            "target_repo/app.py",
            "--line",
            "15",
            "--mitigation",
            "Bound parameter query implemented.",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["test"] == 10
    assert parsed["severity"] == "Critical"
    assert parsed["cwe"] == 89
    assert "[CRITICAL] CWE-89:" in parsed["title"]
    assert "codeql" in parsed["tags"]
    assert "Bound parameter query" in parsed["mitigation"]
