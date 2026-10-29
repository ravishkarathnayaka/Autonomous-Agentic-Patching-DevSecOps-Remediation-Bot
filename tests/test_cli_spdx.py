from pathlib import Path
from click.testing import CliRunner
import json
from cli.export_spdx import export_spdx_command, parse_requirements_file


def test_parse_requirements_file(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("flask==3.0.0\nrequests>=2.31.0\n# comment line\npytest\n", encoding="utf-8")

    packages = parse_requirements_file(req_file)
    assert len(packages) == 3
    assert packages[0]["name"] == "flask"
    assert packages[0]["version"] == "3.0.0"
    assert packages[0]["purl"] == "pkg:pypi/flask@3.0.0"
    assert packages[1]["name"] == "requests"
    assert packages[1]["version"] == "2.31.0"
    assert packages[2]["name"] == "pytest"


def test_cli_export_spdx(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("pydantic==2.5.0\nfastapi==0.104.0\n", encoding="utf-8")
    output_file = tmp_path / "sbom.spdx.json"

    runner = CliRunner()
    result = runner.invoke(export_spdx_command, [
        "--project", "test-project",
        "--requirements", str(req_file),
        "--output", str(output_file)
    ])

    assert result.exit_code == 0
    assert "Successfully generated SPDX 2.3 SBOM" in result.output
    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        sbom_data = json.load(f)

    assert sbom_data["spdxVersion"] == "SPDX-2.3"
    assert sbom_data["name"] == "test-project SBOM"
    # Root package + 2 requirement packages = 3 packages
    assert len(sbom_data["packages"]) == 3
    package_names = [p["name"] for p in sbom_data["packages"]]
    assert "test-project" in package_names
    assert "pydantic" in package_names
    assert "fastapi" in package_names
