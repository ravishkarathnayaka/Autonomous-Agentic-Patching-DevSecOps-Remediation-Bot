"""Automated benchmark evaluation script producing Markdown summary tables."""

from pathlib import Path
import sys
import time
from typing import Dict, List

from agent_engine.graph import RemediationGraph
from agent_engine.llm.client import get_llm_client
from agent_engine.state import Finding, RemediationState, RemediationStatus
from agent_engine.tools.report_parsers import load_findings_from_file
from agent_engine.tools.sandbox_executor import SandboxExecutor


def run_benchmarks_and_generate_markdown(fixtures_dir: Path, target_dir: Path) -> str:
    """Run benchmark against all fixture scanners and generate markdown table."""
    fixture_files = sorted(list(fixtures_dir.glob("*_findings.json")))
    all_findings: List[Finding] = []

    for f in fixture_files:
        try:
            parsed = load_findings_from_file(f)
            if parsed:
                all_findings.append(parsed[0])  # Benchmark primary finding
        except Exception:
            pass

    llm = get_llm_client(provider="mock")
    executor = SandboxExecutor(force_local=True)
    graph = RemediationGraph(llm_client=llm, sandbox_executor=executor, max_retries=1)

    rows: List[str] = [
        "# DevSecOps Remediation Bot Benchmark Results",
        "",
        "| CWE ID | Scanner | Vulnerability Title | Severity | Status | Retries | Duration |",
        "|:-------|:--------|:--------------------|:---------|:-------|:--------|:---------|"
    ]

    total_time = 0.0
    passed_count = 0

    for finding in all_findings:
        t0 = time.time()
        state = RemediationState(finding=finding, target_repo_path=str(target_dir), max_retries=1)
        res = graph.run(state)
        elapsed = time.time() - t0
        total_time += elapsed

        cwe_str = finding.cwe_ids[0] if finding.cwe_ids else "N/A"
        status_badge = "✅ PASSED" if res.status == RemediationStatus.PR_READY else "❌ FAILED"
        if res.status == RemediationStatus.PR_READY:
            passed_count += 1

        rows.append(
            f"| `{cwe_str}` | `{finding.scanner}` | {finding.title[:30]} | `{finding.severity.value}` | {status_badge} | {res.retry_count} | {elapsed:.2f}s |"
        )

    pass_rate = (passed_count / len(all_findings) * 100) if all_findings else 0
    rows.extend([
        "",
        f"**Summary**: {passed_count}/{len(all_findings)} passed ({pass_rate:.1f}%) in {total_time:.2f}s total execution time.",
        ""
    ])

    return "\n".join(rows)


if __name__ == "__main__":
    md = run_benchmarks_and_generate_markdown(Path("./tests/fixtures"), Path("./target_repo"))
    print(md)
