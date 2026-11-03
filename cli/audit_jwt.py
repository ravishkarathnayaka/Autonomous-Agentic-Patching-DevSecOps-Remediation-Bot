"""CLI tool to audit JSON Web Token (JWT) posture against OWASP best practices."""

import json
import sys
from typing import Optional
import click

from agent_engine.tools.jwt_security_auditor import JwtSecurityAuditor


@click.command(name="audit-jwt", help="Audit an encoded JWT for algorithm weaknesses, missing expiration, and syntax flaws.")
@click.option(
    "--token",
    "-t",
    "token",
    required=True,
    help="Raw JWT string (header.payload.signature).",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Output JSON file path. Defaults to stdout.",
)
def audit_jwt(token: str, output_file: Optional[str]) -> None:
    """Audit JWT string and report findings."""
    issues = JwtSecurityAuditor.audit_token(token)
    results = {
        "token_snippet": token[:15] + "..." if len(token) > 15 else token,
        "is_compliant": len(issues) == 0,
        "issue_count": len(issues),
        "issues": [
            {
                "severity": i.severity,
                "issue": i.issue,
                "recommendation": i.recommendation,
            }
            for i in issues
        ],
    }

    formatted = json.dumps(results, indent=2)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(formatted)
        click.echo(f"JWT audit report written to {output_file}")
    else:
        click.echo(formatted)

    if issues:
        sys.exit(1)


if __name__ == "__main__":
    audit_jwt()
