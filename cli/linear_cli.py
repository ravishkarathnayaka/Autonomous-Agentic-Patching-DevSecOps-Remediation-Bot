"""CLI tool to generate Linear DevSecOps issue payload."""

import json
from pathlib import Path
from typing import Optional
import click

from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.linear_formatter import LinearTicketFormatter


@click.command(name="linear-issue", help="Format a vulnerability finding into Linear issue payload.")
@click.option(
    "--team",
    "-t",
    "team_id",
    default="team_sec_01",
    help="Linear Team ID.",
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
    "--patch-summary",
    "patch_summary",
    default=None,
    help="Optional summary note of automated remediation status.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Save JSON payload to file instead of stdout.",
)
def linear_issue(
    team_id: str,
    scanner: str,
    rule_id: str,
    title: str,
    severity: str,
    file_path: str,
    start_line: int,
    patch_summary: Optional[str],
    output_file: Optional[str],
):
    """CLI to format security finding into Linear issue payload."""
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

    payload = LinearTicketFormatter.format_issue_payload(
        finding=finding,
        team_id=team_id,
        patch_summary=patch_summary,
    )

    rendered = json.dumps(payload, indent=2)

    if output_file:
        Path(output_file).write_text(rendered, encoding="utf-8")
        click.echo(f"Linear issue payload written to {output_file}")
    else:
        click.echo(rendered)


if __name__ == "__main__":
    linear_issue()
