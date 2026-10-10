from pathlib import Path
from click.testing import CliRunner
from cli.policy_cli import policy_check_command


def test_cli_policy_check():
    policy_path = Path(__file__).parent.parent / "rules" / "pci-dss-compliance-policy.yml"
    runner = CliRunner()
    result = runner.invoke(policy_check_command, ["--policy", str(policy_path)])

    assert result.exit_code == 0
    assert "Policy file 'pci-dss-compliance-policy.yml' is valid!" in result.output
    assert "Compliance Profile: PCI-DSS" in result.output


def test_cli_policy_check_invalid(tmp_path: Path):
    invalid_file = tmp_path / "bad_policy.yml"
    invalid_file.write_text("just a string, not yaml dict", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(policy_check_command, ["--policy", str(invalid_file)])

    assert result.exit_code == 1
    assert "Error: Policy file is empty or not a valid YAML dictionary" in result.output
