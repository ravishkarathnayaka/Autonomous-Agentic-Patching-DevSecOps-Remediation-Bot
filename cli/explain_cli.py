"""CLI tool to display remediation patterns and rationale for security vulnerabilities."""

import sys
from typing import Optional
import click

from agent_engine.knowledge_base import get_cwe_pattern, list_supported_cwes


@click.command(name="explain", help="Display remediation guidance and secure patterns for a given CWE.")
@click.option(
    "--cwe",
    "-c",
    required=False,
    help="Target CWE ID to explain (e.g. CWE-89, CWE-78, CWE-22, CWE-798)."
)
@click.option(
    "--list-all",
    "-l",
    is_flag=True,
    help="List all supported CWE patterns in the knowledge base."
)
def explain_command(cwe: Optional[str], list_all: bool) -> None:
    """Print remediation advice and pattern examples."""
    if list_all or not cwe:
        supported = list_supported_cwes()
        click.secho("Supported CWE Knowledge Base Patterns:", fg="cyan", bold=True)
        for c in supported:
            pat = get_cwe_pattern(c)
            name = pat.name if pat else ""
            click.echo(f"  - {c:10}: {name}")
        return

    pattern = get_cwe_pattern(cwe)
    if not pattern:
        click.secho(f"[!] CWE '{cwe}' not found in remediation knowledge base.", fg="yellow")
        click.echo(f"Available: {', '.join(list_supported_cwes())}")
        sys.exit(1)

    click.echo("=" * 60)
    click.secho(f"REMEDIATION GUIDANCE: {pattern.cwe_id} - {pattern.name}", fg="green", bold=True)
    click.echo(f"OWASP Category: {pattern.owasp_category}")
    click.echo("=" * 60)
    click.echo(f"\nDescription:\n  {pattern.description}")
    click.echo(f"\nPatch Instructions:\n  {pattern.patch_instructions}")
    click.secho("\n[Insecure Anti-Pattern]:", fg="red", bold=True)
    click.echo(pattern.insecure_anti_pattern)
    click.secho("\n[Secure Pattern]:", fg="green", bold=True)
    click.echo(pattern.secure_pattern)
    click.echo()


if __name__ == "__main__":
    explain_command()
