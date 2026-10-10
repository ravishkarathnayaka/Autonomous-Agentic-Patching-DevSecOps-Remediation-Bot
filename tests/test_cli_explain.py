from click.testing import CliRunner
from cli.explain_cli import explain_command


def test_cli_explain_specific_cwe():
    runner = CliRunner()
    result = runner.invoke(explain_command, ["--cwe", "CWE-89"])
    assert result.exit_code == 0
    assert "REMEDIATION GUIDANCE: CWE-89 - SQL Injection" in result.output
    assert "Secure Pattern" in result.output
    assert "parameterized" in result.output.lower()


def test_cli_explain_list_all():
    runner = CliRunner()
    result = runner.invoke(explain_command, ["--list-all"])
    assert result.exit_code == 0
    assert "Supported CWE Knowledge Base Patterns" in result.output
    assert "CWE-89" in result.output
    assert "CWE-78" in result.output
