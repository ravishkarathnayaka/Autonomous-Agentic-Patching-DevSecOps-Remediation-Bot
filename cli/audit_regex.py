"""CLI tool to audit regular expressions for catastrophic backtracking and ReDoS."""

import sys
import click

from agent_engine.tools.regex_complexity_auditor import RegexComplexityAuditor


@click.command(name="audit-regex", help="Audit regular expressions for ReDoS and catastrophic backtracking hazards.")
@click.argument("patterns", nargs=-1)
@click.option(
    "--file",
    "-f",
    "pattern_file",
    type=click.Path(exists=True, dir_okay=False),
    help="Optional file containing newline-delimited regular expression patterns.",
)
def audit_regex(patterns, pattern_file):
    """Audit pattern arguments or patterns read from a file."""
    all_patterns = list(patterns)

    if pattern_file:
        from pathlib import Path
        lines = Path(pattern_file).read_text(encoding="utf-8").splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                all_patterns.append(stripped)

    if not all_patterns:
        click.echo("No regex patterns specified. Pass patterns as arguments or use --file.", err=True)
        sys.exit(1)

    has_failures = False
    for pat in all_patterns:
        is_safe, warnings = RegexComplexityAuditor.audit_pattern(pat)
        if is_safe:
            click.echo(f"[PASS] `{pat}`: Safe regular expression.")
        else:
            has_failures = True
            click.echo(f"[FAIL] `{pat}`: Hazardous regular expression!")
            for w in warnings:
                click.echo(f"  - {w}")

    if has_failures:
        sys.exit(1)


if __name__ == "__main__":
    audit_regex()
