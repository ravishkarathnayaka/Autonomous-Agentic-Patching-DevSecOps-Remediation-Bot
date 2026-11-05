"""CLI tool to audit SVG files for XXE and script injection vulnerabilities."""

import sys
from pathlib import Path
import click

from agent_engine.tools.svg_security_auditor import SvgSecurityAuditor


@click.command(name="audit-svg", help="Audit SVG files for XXE and Stored XSS vectors.")
@click.argument("svg_paths", nargs=-1, type=click.Path(exists=True, dir_okay=False))
def audit_svg(svg_paths):
    """Scan one or more SVG files for XXE and XSS vectors."""
    if not svg_paths:
        click.echo("No SVG files specified. Please provide at least one path.", err=True)
        sys.exit(1)

    total_files = len(svg_paths)
    vulnerable_files = 0

    for path_str in svg_paths:
        path = Path(path_str)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            click.echo(f"Error reading {path_str}: {e}", err=True)
            vulnerable_files += 1
            continue

        is_safe, violations = SvgSecurityAuditor.audit_svg(content)
        if is_safe:
            click.echo(f"[PASS] {path_str}: No XXE/XSS defects detected.")
        else:
            vulnerable_files += 1
            click.echo(f"[FAIL] {path_str} has {len(violations)} security violation(s):")
            for violation in violations:
                click.echo(f"  - {violation}")

    if vulnerable_files > 0:
        click.echo(f"\nAudit completed: {vulnerable_files}/{total_files} file(s) failed.")
        sys.exit(1)
    else:
        click.echo(f"\nAudit completed: all {total_files} file(s) passed security checks.")


if __name__ == "__main__":
    audit_svg()
