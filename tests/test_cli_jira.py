import json
from click.testing import CliRunner
from cli.jira_cli import jira_issue


def test_cli_jira_issue_stdout():
    runner = CliRunner()
    result = runner.invoke(
        jira_issue,
        [
            "--project",
            "PRODSEC",
            "--scanner",
            "codeql",
            "--rule-id",
            "CWE-89",
            "--title",
            "SQL Injection in searchHandler",
            "--severity",
            "CRITICAL",
            "--file",
            "server/db.py",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    fields = parsed["fields"]
    assert fields["project"]["key"] == "PRODSEC"
    assert fields["priority"]["name"] == "Highest"
    assert "[CRITICAL] CWE-89:" in fields["summary"]
    assert "codeql" in fields["labels"]
