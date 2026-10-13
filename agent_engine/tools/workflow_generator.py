"""Utility to generate tailored GitHub Actions DevSecOps remediation CI workflows."""

from typing import List


def generate_github_workflow(
    scanners: List[str] = None,
    branch: str = "main",
    enable_sandbox: bool = True
) -> str:
    """Generate YAML for a GitHub Actions workflow that executes the remediation bot on schedule/PR.

    Args:
        scanners: List of scanners to run (e.g. ['semgrep', 'trivy', 'gitleaks']).
        branch: Target repository branch.
        enable_sandbox: Whether Docker sandbox is enabled in CI.

    Returns:
        Workflow YAML content.
    """
    scanners = scanners or ["semgrep", "trivy"]
    scanner_steps = []

    if "semgrep" in scanners:
        scanner_steps.append(
            "      - name: Run Semgrep SAST\n"
            "        run: semgrep scan --json --output=semgrep.json target_repo"
        )
    if "trivy" in scanners:
        scanner_steps.append(
            "      - name: Run Trivy SCA\n"
            "        run: trivy fs --format json --output trivy.json target_repo"
        )
    if "gitleaks" in scanners:
        scanner_steps.append(
            "      - name: Run Gitleaks Secret Scan\n"
            "        run: gitleaks detect --report-format json --report-path gitleaks.json"
        )

    joined_scanners = "\n".join(scanner_steps)

    yaml_template = f"""name: Autonomous DevSecOps Remediation Bot

on:
  schedule:
    - cron: '0 2 * * *'  # Run nightly at 2:00 AM UTC
  workflow_dispatch:

jobs:
  remediate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'
          cache: 'pip'

      - name: Install Bot & Scanners
        run: |
          pip install -r requirements.txt
          pip install semgrep

{joined_scanners}

      - name: Run Remediation Engine
        run: |
          python cli/main.py --report semgrep.json --target target_repo --sandbox-mode {'docker' if enable_sandbox else 'local'}
"""
    return yaml_template.strip()
