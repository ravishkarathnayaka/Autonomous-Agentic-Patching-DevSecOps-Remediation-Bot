"""CLI tool to generate in-toto SLSA Level 3 Provenance attestation statements."""

import json
from pathlib import Path
import sys
import click

from agent_engine.tools.slsa_provenance_generator import SLSAProvenanceGenerator


@click.command(name="attest-slsa", help="Generate an in-toto SLSA Provenance predicate for build artifacts.")
@click.option(
    "--artifact",
    "-a",
    "artifact_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to the build artifact (binary, bundle, zip) to hash and attest."
)
@click.option(
    "--repo",
    "-r",
    "repo_uri",
    required=True,
    help="Source code repository URI (e.g. https://github.com/org/repo)."
)
@click.option(
    "--commit",
    "-c",
    "commit_sha",
    required=True,
    help="Cryptographic git commit hash of the verified source code."
)
@click.option(
    "--output",
    "-o",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output file path for SLSA JSON provenance document."
)
def attest_slsa_command(artifact_path: Path, repo_uri: str, commit_sha: str, output_path: Path) -> None:
    """Read artifact bytes and write in-toto SLSA provenance document."""
    try:
        artifact_bytes = artifact_path.read_bytes()
        provenance = SLSAProvenanceGenerator.generate_provenance(
            artifact_name=artifact_path.name,
            artifact_bytes=artifact_bytes,
            repo_uri=repo_uri,
            commit_sha=commit_sha
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(provenance, f, indent=2)

        click.secho(
            f"[✓] Successfully generated SLSA Level 3 Provenance for '{artifact_path.name}': {output_path}",
            fg="green",
            bold=True
        )
    except Exception as e:
        click.secho(f"[!] Error generating SLSA Provenance: {e}", fg="red", err=True)
        sys.exit(1)


if __name__ == "__main__":
    attest_slsa_command()
