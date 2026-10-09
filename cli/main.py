"""CLI entry point for Autonomous Agentic Patching & DevSecOps Remediation Bot."""

import logging
from pathlib import Path
import sys
from typing import List, Optional

import click

from agent_engine.graph import RemediationGraph
from agent_engine.llm.client import get_llm_client
from agent_engine.state import Finding, RemediationState, RemediationStatus
from agent_engine.tools.report_parsers import load_findings_from_file
from agent_engine.tools.sandbox_executor import SandboxExecutor
from agent_engine.tools.sarif_exporter import export_findings_to_sarif
from agent_engine.tools.notification_dispatcher import NotificationDispatcher
from agent_engine.telemetry import TelemetryTracker

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("remediation_bot")


def _print_banner() -> None:
    banner = """
========================================================================
   AUTONOMOUS AGENTIC PATCHING & DEVSECOPS REMEDIATION BOT
      Triage -> Patch Agent -> Sandbox Verifier -> PR Agent
========================================================================
"""
    click.echo(click.style(banner, fg="cyan", bold=True))


@click.command(context_settings=dict(help_option_names=["-h", "--help"]))
@click.option(
    "--report",
    "-r",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to Semgrep SAST or Trivy SCA JSON report file."
)
@click.option(
    "--target",
    "-t",
    default="./target_repo",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    show_default=True,
    help="Path to target repository to analyze and remediate."
)
@click.option(
    "--provider",
    "-p",
    default="mock",
    type=click.Choice(["mock", "ollama", "openai", "vllm"], case_sensitive=False),
    show_default=True,
    help="LLM provider: 'mock' for local offline testing, 'ollama' for $0 local models, 'openai' for APIs."
)
@click.option(
    "--model",
    "-m",
    default=None,
    help="Model name (e.g. 'qwen2.5-coder:7b', 'llama3', 'gpt-4o'). Default depends on provider."
)
@click.option(
    "--base-url",
    default=None,
    help="Base URL for LLM endpoint (e.g. http://localhost:11434 for Ollama)."
)
@click.option(
    "--max-retries",
    default=3,
    type=int,
    show_default=True,
    help="Maximum verification feedback retry loops per vulnerability."
)
@click.option(
    "--sandbox-mode",
    type=click.Choice(["auto", "docker", "local"], case_sensitive=False),
    default="auto",
    show_default=True,
    help="Execution sandbox mode: 'docker' runs in container, 'local' runs in subprocess, 'auto' detects."
)
@click.option(
    "--test-file",
    default="test_app.py",
    show_default=True,
    help="Test file or pattern to execute during regression verification."
)
@click.option(
    "--output-pr",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional path to write generated Pull Request markdown output."
)
@click.option(
    "--export-sarif",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional path to export normalized findings as SARIF 2.1.0 JSON."
)
@click.option(
    "--export-telemetry",
    type=click.Path(path_type=Path),
    default=None,
    help="Optional path to export remediation performance telemetry JSON."
)
@click.option(
    "--finding-id",
    default=None,
    help="Filter to remediate only a specific finding ID."
)
@click.option(
    "--simulate-failure",
    is_flag=True,
    default=False,
    help="Instruct mock LLM to simulate a first-attempt failure to test self-healing retry loop."
)
@click.option(
    "--webhook-url",
    default=None,
    help="Optional Slack or Discord incoming webhook URL to broadcast remediation status."
)
def main(
    report: Path,
    target: Path,
    provider: str,
    model: Optional[str],
    base_url: Optional[str],
    max_retries: int,
    sandbox_mode: str,
    test_file: str,
    output_pr: Optional[Path],
    export_sarif: Optional[Path],
    export_telemetry: Optional[Path],
    finding_id: Optional[str],
    simulate_failure: bool,
    webhook_url: Optional[str]
) -> None:
    """Autonomous agentic vulnerability remediation CLI."""
    _print_banner()

    target_dir = target.resolve()
    click.echo(f"[*] Target Repository: {target_dir}")
    click.echo(f"[*] Ingesting Security Scan Report: {report}")
    click.echo(f"[*] LLM Engine: Provider={provider.upper()} Model={model or 'default'}")

    # 1. Ingest findings from report
    try:
        findings: List[Finding] = load_findings_from_file(report)
        click.echo(f"[*] Ingested {len(findings)} findings from {report.name}.")
    except Exception as e:
        click.secho(f"[!] Error parsing report: {e}", fg="red", bold=True)
        sys.exit(1)

    if finding_id:
        findings = [f for f in findings if f.id == finding_id or finding_id in f.rule_id]
        click.echo(f"[*] Filtered to {len(findings)} finding(s) matching '{finding_id}'.")

    if not findings:
        click.secho("[!] No actionable findings found.", fg="yellow")
        sys.exit(0)

    # Optional SARIF export
    if export_sarif:
        try:
            export_findings_to_sarif(findings, output_path=export_sarif)
            click.secho(f"[+] Exported findings to SARIF: {export_sarif}", fg="green")
        except Exception as e:
            logger.error("Failed to export SARIF: %s", e)

    # 2. Configure Sandbox Executor
    force_local = (sandbox_mode.lower() == "local")
    executor = SandboxExecutor(force_local=force_local)
    sb_mode_label = "Docker (Container)" if executor.is_docker_ready() else "Local Subprocess (Process-isolated)"
    click.echo(f"[*] Execution Sandbox Mode: {sb_mode_label}")

    # 3. Configure LLM Client
    llm_client = get_llm_client(
        provider=provider,
        model=model,
        base_url=base_url,
        simulate_retry_failure=simulate_failure
    )

    # 4. Initialize Multi-Agent Remediation Graph
    graph = RemediationGraph(
        llm_client=llm_client,
        sandbox_executor=executor,
        max_retries=max_retries,
        test_file=test_file
    )

    results: List[RemediationState] = []

    # 5. Process each finding through multi-agent state graph
    for idx, finding in enumerate(findings, 1):
        click.echo("\n" + "=" * 60)
        click.secho(f"[{idx}/{len(findings)}] REMEDIATING: {finding.title} [{finding.severity.value}]", fg="yellow", bold=True)
        click.echo(f"     Rule: {finding.rule_id} | CWE: {', '.join(finding.cwe_ids) or 'N/A'}")
        click.echo(f"     Location: {finding.file_path}:{finding.start_line}")

        state = RemediationState(
            finding=finding,
            target_repo_path=str(target_dir),
            max_retries=max_retries
        )

        final_state = graph.run(state)
        results.append(final_state)

        if final_state.status == RemediationStatus.PR_READY:
            click.secho("  -> Remediation VERIFIED and PR Generated!", fg="green", bold=True)
            click.echo(f"     Branch: {final_state.pr_branch}")
            click.echo(f"     Commit: {final_state.commit_sha or 'Staged'}")
        elif final_state.status == RemediationStatus.FAILED:
            click.secho(f"  -> Remediation FAILED: {final_state.last_error_trace}", fg="red", bold=True)
        else:
            click.secho(f"  -> Finished with status: {final_state.status.value}", fg="cyan")

        # Broadcast webhook alerts if configured
        if webhook_url:
            dispatcher = NotificationDispatcher(webhook_url)
            if final_state.status == RemediationStatus.PR_READY:
                dispatcher.dispatch_pr_created(final_state)
            elif final_state.status == RemediationStatus.FAILED:
                dispatcher.dispatch_remediation_failed(final_state)

    # 6. Summary Report
    click.echo("\n" + "=" * 70)
    click.secho("                    REMEDIATION EXECUTION SUMMARY", fg="cyan", bold=True)
    click.echo("=" * 70)

    successful = [s for s in results if s.status == RemediationStatus.PR_READY]
    failed = [s for s in results if s.status == RemediationStatus.FAILED]

    click.echo(f"Total Processed: {len(results)} | Succeeded: {len(successful)} | Failed: {len(failed)}")
    click.echo("-" * 70)
    for s in results:
        status_color = "green" if s.status == RemediationStatus.PR_READY else "red"
        status_text = click.style(f"[{s.status.value}]", fg=status_color, bold=True)
        cwe_str = s.finding.cwe_ids[0] if s.finding.cwe_ids else s.finding.rule_id
        click.echo(f"{status_text:20} {cwe_str:15} Retries: {s.retry_count} | Branch: {s.pr_branch or 'N/A'}")

    # 7. Write PR markdown artifact if requested
    if output_pr and successful:
        try:
            combined_pr = "\n\n---\n\n".join([s.pr_body for s in successful if s.pr_body])
            with open(output_pr, "w", encoding="utf-8") as f:
                f.write(combined_pr)
            click.secho(f"\n[+] Wrote Pull Request markdown description to: {output_pr}", fg="green")
        except Exception as e:
            logger.error("Failed to write PR output file: %s", e)

    # 8. Export Telemetry Report if requested
    if export_telemetry:
        try:
            tracker = TelemetryTracker()
            for s in results:
                tracker.record_attempt(
                    finding_id=s.finding.id,
                    rule_id=s.finding.rule_id,
                    severity=s.finding.severity.value,
                    cwe=s.finding.cwe_ids,
                    duration_seconds=0.0,
                    status=s.status.value,
                    retry_count=s.retry_count,
                    sandbox_passed=(s.status == RemediationStatus.PR_READY)
                )
            tracker.generate_report().export_json(export_telemetry)
            click.secho(f"[+] Wrote Telemetry report to: {export_telemetry}", fg="green")
        except Exception as e:
            logger.error("Failed to export telemetry: %s", e)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
