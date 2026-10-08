# Contributing to Autonomous Agentic Patching & DevSecOps Remediation Bot

Thank you for your interest in contributing to the **Autonomous Agentic Patching & DevSecOps Remediation Bot**! We welcome contributions from software developers, security researchers, DevSecOps practitioners, and AI systems engineers.

This document provides guidelines and workflows for contributing to the repository.

---

## Code of Conduct

All contributors and maintainers are expected to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please report any unacceptable behavior to the project maintainers.

---

## How Can You Contribute?

You can contribute in many ways:
- **Reporting Bugs:** File an issue detailing steps to reproduce, expected vs. actual behavior, and environment details.
- **Proposing Features:** Submit a feature request describing the use case, proposed architecture, and security considerations.
- **Adding Security Scanners:** Write parsers for additional SAST/SCA tools (e.g., Bandit, Snyk, Checkmarx, SonarQube).
- **Expanding Vulnerability Scenarios:** Add new benchmark vulnerabilities to `target_repo/` with regression tests.
- **Enhancing LLM Prompts & Patch Agents:** Improve zero-shot/few-shot prompts for generating surgical diffs.
- **Improving Documentation:** Fix typos, add architecture diagrams, or write tutorials.

---

## Development Setup

### Prerequisites
- Python 3.11+
- Git
- Docker (for ephemeral sandbox execution)
- Node.js 18+ (for web portal development)

### Setting Up the Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/ravishkarathnayaka/Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot.git
   cd "Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot"
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv .venv
   # On Linux/macOS:
   source .venv/bin/activate
   # On Windows PowerShell:
   .venv\Scripts\Activate.ps1
   ```

3. **Install development dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-cov mypy flake8 black
   ```

4. **Verify the test suite passes:**
   ```bash
   python -m pytest tests/ target_repo/test_app.py -v
   ```

---

## Coding Standards & Style

We maintain high code quality standards to ensure safety and maintainability:
- **Formatting:** Code must be formatted with `black` (line length 100).
- **Linting:** Code must pass `flake8` with 0 warnings.
- **Type Checking:** All Python code must be fully type-hinted and pass `mypy agent_engine cli`.
- **Security Isolation:** Code that touches untrusted input or candidate patches must execute inside the Docker sandbox (`network_disabled=True`).

---

## Pull Request Process

1. **Create a topic branch:**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/your-bugfix-name
   ```
2. **Make your changes:** Keep commits atomic, well-documented, and focused.
3. **Run tests and type checks:**
   ```bash
   pytest tests/ target_repo/test_app.py
   mypy agent_engine cli
   flake8 agent_engine cli
   ```
4. **Push your branch and open a PR** using the standard PR template.
5. Address any review feedback promptly.

---

## Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` A new feature or capability
- `fix:` A bug fix
- `docs:` Documentation improvements
- `test:` Adding or refactoring tests
- `refactor:` Code change that neither fixes a bug nor adds a feature
- `ci:` Changes to CI/CD workflows and configuration
- `dev:` Development tooling and environment changes

---

Thank you for helping make autonomous security remediation safer and more accessible!
