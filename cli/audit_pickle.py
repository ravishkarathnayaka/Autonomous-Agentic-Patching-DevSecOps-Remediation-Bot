"""CLI tool to audit serialized files or payloads for pickle deserialization vulnerabilities."""

import base64
import sys
from pathlib import Path
import click

from agent_engine.tools.pickle_safety_inspector import PickleSafetyInspector


@click.command(name="audit-pickle", help="Audit serialized files or base64 streams for dangerous pickle opcodes.")
@click.argument("files", nargs=-1, type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--base64",
    "-b",
    "b64_payload",
    help="Base64-encoded pickle payload string to audit directly.",
)
def audit_pickle(files, b64_payload):
    """Audit binary pickle files or base64 payload strings."""
    if not files and not b64_payload:
        click.echo("Please specify at least one file or pass a --base64 payload.", err=True)
        sys.exit(1)

    has_failures = False

    if b64_payload:
        try:
            raw_bytes = base64.b64decode(b64_payload)
            is_safe, violations = PickleSafetyInspector.inspect_bytes(raw_bytes)
            if is_safe:
                click.echo("[PASS] Base64 payload: No dangerous pickle opcodes detected.")
            else:
                has_failures = True
                click.echo(f"[FAIL] Base64 payload has {len(violations)} security violation(s):")
                for v in violations:
                    click.echo(f"  - {v}")
        except Exception as e:
            click.echo(f"[ERROR] Failed to decode base64 payload: {e}", err=True)
            has_failures = True

    for file_str in files:
        p = Path(file_str)
        try:
            raw_bytes = p.read_bytes()
            is_safe, violations = PickleSafetyInspector.inspect_bytes(raw_bytes)
            if is_safe:
                click.echo(f"[PASS] {file_str}: Safe serialized stream.")
            else:
                has_failures = True
                click.echo(f"[FAIL] {file_str} has {len(violations)} security violation(s):")
                for v in violations:
                    click.echo(f"  - {v}")
        except Exception as e:
            click.echo(f"[ERROR] Reading {file_str}: {e}", err=True)
            has_failures = True

    if has_failures:
        sys.exit(1)


if __name__ == "__main__":
    audit_pickle()
