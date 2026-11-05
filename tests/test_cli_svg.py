from click.testing import CliRunner
from cli.audit_svg import audit_svg


def test_cli_audit_svg_pass(tmp_path):
    safe_svg = tmp_path / "valid.svg"
    safe_svg.write_text("<svg><circle r='10'/></svg>", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(audit_svg, [str(safe_svg)])
    assert result.exit_code == 0
    assert "[PASS]" in result.output


def test_cli_audit_svg_fail(tmp_path):
    evil_svg = tmp_path / "evil.svg"
    evil_svg.write_text("<!DOCTYPE svg [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><svg>&xxe;</svg>", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(audit_svg, [str(evil_svg)])
    assert result.exit_code == 1
    assert "[FAIL]" in result.output
    assert "DOCTYPE" in result.output
