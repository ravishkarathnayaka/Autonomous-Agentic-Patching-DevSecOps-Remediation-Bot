from pathlib import Path
from click.testing import CliRunner
import json
from cli.attest_slsa import attest_slsa_command


def test_cli_attest_slsa(tmp_path: Path):
    artifact = tmp_path / "app-release.tar.gz"
    artifact.write_bytes(b"GZIP_MOCK_BYTES_12345")
    output_file = tmp_path / "provenance.slsa.json"

    runner = CliRunner()
    result = runner.invoke(attest_slsa_command, [
        "--artifact", str(artifact),
        "--repo", "https://github.com/organization/target-service",
        "--commit", "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
        "--output", str(output_file)
    ])

    assert result.exit_code == 0
    assert "Successfully generated SLSA Level 3 Provenance" in result.output
    assert output_file.exists()

    with open(output_file, "r", encoding="utf-8") as f:
        prov = json.load(f)

    assert prov["_type"] == "https://in-toto.io/Statement/v0.1"
    assert prov["predicateType"] == "https://slsa.dev/provenance/v0.2"
    assert prov["subject"][0]["name"] == "app-release.tar.gz"
    assert "sha256" in prov["subject"][0]["digest"]
