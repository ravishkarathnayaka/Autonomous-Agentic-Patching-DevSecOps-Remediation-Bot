from pathlib import Path
from click.testing import CliRunner
import json
from cli.export_cyclonedx import export_cyclonedx_command


def test_cli_export_cyclonedx(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==3.0.0\nrequests>=2.31.0\n", encoding="utf-8")
    output_file = tmp_path / "bom.cyclonedx.json"

    runner = CliRunner()
    result = runner.invoke(export_cyclonedx_command, [
        "--project", "test-api",
        "--requirements", str(req_file),
        "--output", str(output_file)
    ])

    assert result.exit_code == 0
    assert "Successfully generated CycloneDX 1.5 SBOM" in result.output
    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        bom_data = json.load(f)

    assert bom_data["bomFormat"] == "CycloneDX"
    assert bom_data["specVersion"] == "1.5"
    assert bom_data["metadata"]["component"]["name"] == "test-api"
    assert len(bom_data["components"]) == 2
    comp_names = [c["name"] for c in bom_data["components"]]
    assert "flask" in comp_names
    assert "requests" in comp_names
