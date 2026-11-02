import json
from click.testing import CliRunner
from cli.export_vex import export_vex


def test_cli_export_vex_stdout():
    runner = CliRunner()
    result = runner.invoke(
        export_vex,
        [
            "--document-id",
            "https://security.example.com/vex/001",
            "--rule-id",
            "CVE-2023-38545",
            "--title",
            "SOCKS5 heap buffer overflow in curl",
            "--status",
            "fixed",
        ],
    )
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert parsed["@id"] == "https://security.example.com/vex/001"
    assert parsed["statements"][0]["status"] == "fixed"
    assert parsed["statements"][0]["vulnerability"]["name"] == "CVE-2023-38545"
