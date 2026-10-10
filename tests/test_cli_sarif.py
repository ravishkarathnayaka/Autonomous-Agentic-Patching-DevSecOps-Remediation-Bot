from pathlib import Path
from click.testing import CliRunner
import json
from cli.sarif_cli import export_sarif_command


def test_cli_export_sarif(tmp_path: Path):
    fixture_path = Path(__file__).parent / "fixtures" / "bandit_findings.json"
    output_file = tmp_path / "results.sarif"

    runner = CliRunner()
    result = runner.invoke(export_sarif_command, ["--input", str(fixture_path), "--output", str(output_file)])

    assert result.exit_code == 0
    assert "Successfully exported" in result.output
    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)
    assert sarif_data["version"] == "2.1.0"
    assert "$schema" in sarif_data
