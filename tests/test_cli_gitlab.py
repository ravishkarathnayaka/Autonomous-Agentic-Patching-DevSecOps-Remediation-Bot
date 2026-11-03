import json
from click.testing import CliRunner
from cli.gitlab_cli import gitlab_issue


def test_cli_gitlab_issue_stdout():
    runner = CliRunner()
    result = runner.invoke(
        gitlab_issue,
        [
            "--scanner",
            "bearer",
            "--rule-id",
            "CWE-89",
            "--title",
            "SQL Injection in loginHandler",
            "--severity",
            "CRITICAL",
            "--file",
            "backend/auth.py",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "[CRITICAL] Security: CWE-89" in parsed["title"]
    assert parsed["confidential"] is True
    assert parsed["weight"] == 5
    assert "severity::critical" in parsed["labels"]
    assert "scanner::bearer" in parsed["labels"]
