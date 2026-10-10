"""CLI tool to convert any supported scanner report directly to GitHub Code Scanning SARIF format."""

from pathlib import Path
import sys
from typing import Optional
import click

from agent_engine.tools.report_parsers import load_findings_from_file
from agent_engine.tools.sarif_exporter import export_findings_to_sarif


@click.command(name="export-sarif", help="Convert any scanner report to GitHub Code Scanning SARIF 2.1.0.")
@click.option(
    "--input",
    "-i",
    "input_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to raw scanner report file (Semgrep, Trivy, Snyk, SonarQube, etc.)."
)
@click.option(
    "--output",
    "-o",
    "output_path",
    required=True,
    type=click.Path(dir_okay=False, path_type=Path),
    help="Path to output SARIF JSON file."
)
def export_sarif_command(input_path: Path, output_path: Path) -> None:
    """Read findings from report and export as SARIF."""
    try:
        findings = load_findings_from_file(input_path)
        if not findings:
            click.secho(f"Warning: No findings parsed from {input_path}.", fg="yellow")
            sys.exit(0)

        export_findings_to_sarif(findings, output_path=output_path)
        click.secho(f"[✓] Successfully exported {len(findings)} findings to SARIF: {output_path}", fg="green", bold=True)
    except Exception as e:
        click.secho(f"[!] Error exporting SARIF: {e}", fg="red", err=True)
        sys.exit(1)


if __name__ == "__main__":
    export_sarif_command()
