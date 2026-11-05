import json
from click.testing import CliRunner
from cli.linear_cli import linear_issue


def test_cli_linear_issue_stdout():
    runner = CliRunner()
    result = runner.invoke(
        linear_issue,
        [
            "--team",
            "PRODSEC",
            "--scanner",
            "acunetix",
            "--rule-id",
            "CWE-235",
            "--title",
            "HTTP Parameter Pollution",
            "--severity",
            "CRITICAL",
            "--file",
            "target_repo/app.py",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["teamId"] == "PRODSEC"
    assert parsed["priority"] == 1
    assert "[CRITICAL] CWE-235" in parsed["title"]
    assert "acunetix" in parsed["labels"]
