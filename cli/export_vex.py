"""CLI tool to generate standard OpenVEX vulnerability advisories."""

import json
from pathlib import Path
import sys
from typing import List, Optional
import click

from agent_engine.state import Finding, FindingType, RemediationStatus, SeverityLevel
from agent_engine.tools.vex_generator import VexDocumentGenerator


@click.command(name="export-vex", help="Generate an OpenVEX v0.2.0 advisory from finding states.")
@click.option(
    "--document-id",
    "-d",
    "document_id",
    required=True,
    help="Unique URI or URN for this VEX document.",
)
@click.option(
    "--author",
    "-a",
    "author",
    default="Autonomous DevSecOps Bot",
    help="Author or organization emitting the VEX document.",
)
@click.option(
    "--rule-id",
    "-r",
    "rule_id",
    required=True,
    help="Vulnerability identifier (e.g. CVE-2023-1234 or CWE-89).",
)
@click.option(
    "--title",
    "-t",
    "title",
    default="Vulnerability Finding",
    help="Brief title of the vulnerability.",
)
@click.option(
    "--status",
    "-s",
    "status",
    type=click.Choice(["fixed", "affected", "under_investigation"], case_sensitive=False),
    default="fixed",
    help="Exploitability status.",
)
@click.option(
    "--product",
    "-p",
    "product_purl",
    default="pkg:generic/target-repo@1.0.0",
    help="Package URL (PURL) of the affected component.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Output JSON file path. Defaults to stdout.",
)
def export_vex(
    document_id: str,
    author: str,
    rule_id: str,
    title: str,
    status: str,
    product_purl: str,
    output_file: Optional[str],
) -> None:
    """Generate OpenVEX document and write to stdout or file."""
    finding = Finding(
        id="finding-01",
        scanner="cli",
        finding_type=FindingType.SAST,
        rule_id=rule_id,
        title=title,
        description=f"Finding identified for {rule_id}",
        severity=SeverityLevel.HIGH,
        file_path="src/main.py",
    )

    status_enum_map = {
        "fixed": RemediationStatus.VERIFIED,
        "affected": RemediationStatus.INITIALIZED,
        "under_investigation": RemediationStatus.FAILED,
    }
    statuses = {"finding-01": status_enum_map[status.lower()]}

    doc = VexDocumentGenerator.generate_openvex(
        document_id=document_id,
        author=author,
        findings=[finding],
        remediation_statuses=statuses,
        product_id=product_purl,
    )

    formatted = json.dumps(doc, indent=2)
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(formatted)
        click.echo(f"OpenVEX document successfully written to {output_file}")
    else:
        click.echo(formatted)


if __name__ == "__main__":
    export_vex()
