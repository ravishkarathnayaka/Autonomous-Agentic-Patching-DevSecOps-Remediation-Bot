"""CLI tool to generate OWASP DefectDojo v2 finding payload."""

import json
from pathlib import Path
from typing import Optional
import click

from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.defectdojo_formatter import DefectDojoFormatter


@click.command(name="defectdojo-finding", help="Format a vulnerability finding into DefectDojo API v2 payload.")
@click.option(
    "--test-id",
    "-t",
    "test_id",
    type=int,
    default=1,
    help="DefectDojo Test engagement ID.",
)
@click.option(
    "--scanner",
    "-s",
    "scanner",
    default="semgrep",
    help="Name of security scanner.",
)
@click.option(
    "--rule-id",
    "-r",
    "rule_id",
    required=True,
    help="Security rule or vulnerability ID.",
)
@click.option(
    "--title",
    "title",
    required=True,
    help="Summary or title of the finding.",
)
@click.option(
    "--severity",
    "-v",
    "severity",
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
    default="HIGH",
    help="Normalized severity level.",
)
@click.option(
    "--file",
    "-f",
    "file_path",
    default="target_repo/app.py",
    help="Target vulnerable file path.",
)
@click.option(
    "--line",
    "-l",
    "start_line",
    type=int,
    default=1,
    help="Starting line number of finding.",
)
@click.option(
    "--mitigation",
    "-m",
    "mitigation",
    default=None,
    help="Remediation or mitigation summary.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Save JSON payload to file instead of stdout.",
)
def defectdojo_finding(
    test_id: int,
    scanner: str,
    rule_id: str,
    title: str,
    severity: str,
    file_path: str,
    start_line: int,
    mitigation: Optional[str],
    output_file: Optional[str],
):
    """CLI to format security finding into DefectDojo payload."""
    finding = Finding(
        id=f"{scanner.lower()}-{rule_id.lower()}",
        scanner=scanner,
        finding_type=FindingType.SAST,
        rule_id=rule_id,
        title=title,
        description=f"Automated vulnerability detection for {rule_id}",
        severity=SeverityLevel(severity.upper()),
        cwe_ids=[rule_id] if rule_id.startswith("CWE-") else [],
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
    )

    payload = DefectDojoFormatter.format_finding(
        finding=finding,
        test_id=test_id,
        is_verified=True,
        mitigation_summary=mitigation,
    )

    rendered = json.dumps(payload, indent=2)

    if output_file:
        Path(output_file).write_text(rendered, encoding="utf-8")
        click.echo(f"DefectDojo payload written to {output_file}")
    else:
        click.echo(rendered)


if __name__ == "__main__":
    defectdojo_finding()
