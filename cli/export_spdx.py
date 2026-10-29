"""CLI tool to generate Linux Foundation standard SPDX 2.3 JSON Software Bill of Materials (SBOM)."""

import json
from pathlib import Path
import re
import sys
from typing import Dict, List, Optional
import click

from agent_engine.tools.spdx_generator import SPDXGenerator


def parse_requirements_file(req_path: Path) -> List[Dict[str, str]]:
    """Parse python requirements.txt into package name and version pairs."""
    packages: List[Dict[str, str]] = []
    if not req_path.exists():
        return packages

    with open(req_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Match package==version or package>=version
            match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|<=|~=)\s*([a-zA-Z0-9_\-\.]+)", line)
            if match:
                packages.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "purl": f"pkg:pypi/{match.group(1)}@{match.group(2)}"
                })
            else:
                pkg_name = line.split(";")[0].split()[0]
                if pkg_name:
                    packages.append({
                        "name": pkg_name,
                        "version": "latest",
                        "purl": f"pkg:pypi/{pkg_name}@latest"
                    })
    return packages


@click.command(name="export-spdx", help="Generate an SPDX 2.3 JSON SBOM from requirements or dependencies.")
@click.option(
    "--project",
    "-p",
    "project_name",
    required=True,
    help="Name of the software project or repository."
)
@click.option(
    "--requirements",
    "-r",
    "req_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Optional path to requirements.txt to populate package inventory."
)
@click.option(
    "--output",
    "-o",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Output file path for SPDX 2.3 JSON document."
)
def export_spdx_command(project_name: str, req_path: Optional[Path], output_path: Path) -> None:
    """Generate and write SPDX 2.3 JSON SBOM document."""
    try:
        packages: List[Dict[str, str]] = []
        if req_path:
            packages = parse_requirements_file(req_path)

        sbom = SPDXGenerator.generate_sbom(project_name=project_name, packages=packages)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)

        click.secho(
            f"[✓] Successfully generated SPDX 2.3 SBOM for '{project_name}' with {len(packages)} packages: {output_path}",
            fg="green",
            bold=True
        )
    except Exception as e:
        click.secho(f"[!] Error generating SPDX SBOM: {e}", fg="red", err=True)
        sys.exit(1)


if __name__ == "__main__":
    export_spdx_command()
