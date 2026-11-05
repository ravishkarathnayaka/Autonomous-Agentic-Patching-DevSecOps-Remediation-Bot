from click.testing import CliRunner
from cli.audit_regex import audit_regex


def test_cli_audit_regex_pass():
    runner = CliRunner()
    result = runner.invoke(audit_regex, ["^[a-zA-Z0-9_]+$"])
    assert result.exit_code == 0
    assert "[PASS]" in result.output


def test_cli_audit_regex_fail():
    runner = CliRunner()
    result = runner.invoke(audit_regex, ["(a+)+"])
    assert result.exit_code == 1
    assert "[FAIL]" in result.output
    assert "Nested quantifiers" in result.output


def test_cli_audit_regex_file(tmp_path):
    file = tmp_path / "regexes.txt"
    file.write_text("^[0-9]+$\n(x+)+\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(audit_regex, ["--file", str(file)])
    assert result.exit_code == 1
    assert "[PASS]" in result.output
    assert "[FAIL]" in result.output
