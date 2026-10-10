"""CLI tool to validate custom DevSecOps remediation policy YAML files."""

from pathlib import Path
import sys
import click
import yaml

from agent_engine.policy_engine import RemediationPolicyEngine


@click.command(name="policy-check", help="Validate remediation policy YAML against governance schema.")
@click.option(
    "--policy",
    "-p",
    "policy_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to remediation policy YAML file."
)
def policy_check_command(policy_path: Path) -> None:
    """Validate policy YAML structure and thresholds."""
    try:
        with open(policy_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not data or not isinstance(data, dict):
            click.secho("[!] Error: Policy file is empty or not a valid YAML dictionary.", fg="red", err=True)
            sys.exit(1)

        engine = RemediationPolicyEngine.from_yaml_file(policy_path)
        policy = engine.policy

        click.secho(f"[✓] Policy file '{policy_path.name}' is valid!", fg="green", bold=True)
        click.echo(f"    - Min CVSS: {policy.min_cvss}")
        click.echo(f"    - Allowed Severities: {', '.join(sorted(policy.allowed_severities))}")
        click.echo(f"    - Banned CWEs: {', '.join(sorted(policy.banned_cwes)) or 'None'}")
        click.echo(f"    - Sandbox Enforced: {policy.require_sandbox}")
        click.echo(f"    - Compliance Profile: {policy.compliance_profile or 'STANDARD'}")

    except Exception as e:
        click.secho(f"[!] Policy validation failed: {e}", fg="red", err=True)
        sys.exit(1)


if __name__ == "__main__":
    policy_check_command()
