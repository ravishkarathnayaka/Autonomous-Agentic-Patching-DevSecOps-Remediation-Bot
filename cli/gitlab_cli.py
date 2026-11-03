"""CLI tool to generate GitLab DevSecOps issue payload."""

import json
from pathlib import Path
from typing import Optional
import click

from agent_engine.state import Finding, FindingType, SeverityLevel
from agent_engine.tools.gitlab_issue_formatter import GitlabIssueFormatter


@click.command(name="gitlab-issue", help="Format a vulnerability finding into GitLab REST API v4 issue payload.")
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
    "-t",
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
    default="src/app.py",
    help="Relative path to affected source file.",
)
@click.option(
    "--confidential/--public",
    default=True,
    help="Whether to mark the issue as confidential in GitLab.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Output JSON file path. Defaults to stdout.",
)
def gitlab_issue(
    scanner: str,
    rule_id: str,
    title: str,
    severity: str,
    file_path: str,
    confidential: bool,
    output_file: Optional[str],
) -> None:
    """Format GitLab issue JSON."""
    finding = Finding(
        id="gitlab-cli-finding-01",
        scanner=scanner,
        finding_type=FindingType.SAST,
        rule_id=rule_id,
        title=title,
        description=f"Automated vulnerability detection for {rule_id} in {file_path}",
        severity=SeverityLevel(severity.upper()),
        file_path=file_path,
        start_line=1,
    )

    payload = GitlabIssueFormatter.format_issue_payload(
        finding=finding,
        confidential=confidential,
        patch_summary="Patch synthesized and sandbox verified by Autonomous DevSecOps Bot.",
    )

    formatted = json.dumps(payload, indent=2)
    if output_file:
        Path(output_file).parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(formatted)
        click.echo(f"GitLab issue payload written to {output_file}")
    else:
        click.echo(formatted)


if __name__ == "__main__":
    gitlab_issue()
