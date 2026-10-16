# Developer Integration Quickstart Guide

Get up and running with the **Autonomous Agentic Patching & DevSecOps Remediation Bot** in under 5 minutes.

---

## 1. Prerequisites

- **Python:** 3.10, 3.11, or 3.12
- **Docker:** (Optional, recommended for sandboxed test verification)
- **Node.js:** v18+ (Optional, for web portal dashboard)
- **Git:** 2.30+

---

## 2. Installation

Clone the repository and install all dependencies:

```bash
git clone https://github.com/ravishkarathnayaka/Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot.git
cd Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot

# Create and activate virtual environment
python -m venv venv
# On Linux/macOS:
source venv/bin/activate
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1

# Install requirements
pip install -r requirements.txt
```

---

## 3. Environment Configuration

Create a `.env` file in the project root:

```ini
# LLM Provider Configuration
LLM_PROVIDER=openai             # Options: openai, gemini, anthropic, ollama
OPENAI_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
ANTHROPIC_API_KEY=your_key_here

# Local Ollama fallback (if offline)
OLLAMA_BASE_URL=http://localhost:11434

# Git / GitHub Integration
GITHUB_TOKEN=ghp_your_token_here
REMEDIATION_BRANCH_PREFIX=auto-patch/

# Sandbox Execution Mode
SANDBOX_ENGINE=docker            # Options: docker, gvisor, local
```

---

## 4. Running a Remediation Cycle

### Step 1: Scan your Target Repository
Run Bandit, Semgrep, Trivy, or any of the 16 supported scanners:
```bash
bandit -r target_repo/ -f json -o bandit_findings.json
```

### Step 2: Trigger Autonomous Remediation
```bash
python cli/main.py remediate \
  --findings bandit_findings.json \
  --target target_repo/ \
  --sandbox docker \
  --auto-pr
```

### Step 3: View Executive Security Posture Report
```bash
python cli/main.py report \
  --findings bandit_findings.json \
  --format markdown
```

---

## 5. Running the Test Suite

```bash
# Run all unit tests
pytest tests/

# Run target repo regression tests
pytest target_repo/test_app.py
```

---

## 6. Extending with a Custom Scanner Parser

To add a new vulnerability scanner parser:
1. Create `agent_engine/tools/my_scanner_parser.py` subclassing or implementing `parse(report_path_or_content)`.
2. Add a test fixture in `tests/fixtures/my_scanner_findings.json`.
3. Add unit tests in `tests/test_my_scanner_parser.py`.
4. Register the scanner in `agent_engine/orchestrator.py`.
