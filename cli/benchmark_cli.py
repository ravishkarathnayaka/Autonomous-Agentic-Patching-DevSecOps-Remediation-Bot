"""CLI tool to execute multi-CWE synthetic remediation benchmarks."""

from pathlib import Path
import sys
import time
from typing import Dict, List
import click

from agent_engine.graph import RemediationGraph
from agent_engine.llm.client import get_llm_client
from agent_engine.state import Finding, RemediationState, RemediationStatus
from agent_engine.tools.report_parsers import load_findings_from_file
from agent_engine.tools.sandbox_executor import SandboxExecutor


@click.command(name="benchmark", help="Run synthetic security remediation benchmarks across CWE test fixtures.")
@click.option(
    "--fixtures-dir",
    default="./tests/fixtures",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Path to test fixtures directory."
)
@click.option(
    "--target-dir",
    default="./target_repo",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="Path to target repo directory."
)
def benchmark_command(fixtures_dir: Path, target_dir: Path) -> None:
    """Run remediation benchmark against test fixtures."""
    click.secho("\n=== RUNNING DEVSECOPS BOT BENCHMARK SUITE ===", fg="cyan", bold=True)
    start_time = time.time()

    # Load findings from fixtures
    all_findings: List[Finding] = []
    fixture_files = list(fixtures_dir.glob("*_findings.json"))
    for f in fixture_files:
        try:
            parsed = load_findings_from_file(f)
            all_findings.extend(parsed[:2])  # Sample top 2 per scanner
        except Exception:
            pass

    if not all_findings:
        click.secho("No test findings discovered in fixtures directory.", fg="yellow")
        sys.exit(0)

    llm = get_llm_client(provider="mock")
    executor = SandboxExecutor(force_local=True)
    graph = RemediationGraph(llm_client=llm, sandbox_executor=executor, max_retries=1)

    passed_count = 0
    total_retries = 0

    for idx, f in enumerate(all_findings, 1):
        state = RemediationState(finding=f, target_repo_path=str(target_dir), max_retries=1)
        res = graph.run(state)
        if res.status == RemediationStatus.PR_READY:
            passed_count += 1
        total_retries += res.retry_count

    duration = time.time() - start_time
    pass_rate = (passed_count / len(all_findings)) * 100 if all_findings else 0

    click.echo("-" * 50)
    click.secho(f"Benchmark Completed in {duration:.2f}s", fg="green", bold=True)
    click.echo(f"Total Scenarios Evaluated: {len(all_findings)}")
    click.echo(f"Successfully Remediated:  {passed_count} ({pass_rate:.1f}%)")
    click.echo(f"Total Retry Iterations:   {total_retries}")
    click.echo("-" * 50)


if __name__ == "__main__":
    benchmark_command()
