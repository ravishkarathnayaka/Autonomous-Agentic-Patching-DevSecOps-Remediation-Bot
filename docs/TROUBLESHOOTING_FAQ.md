# Enterprise FAQ & Troubleshooting Guide

Frequently asked questions and operational runbooks for maintaining the **Autonomous DevSecOps Remediation Bot**.

---

## ❓ Frequently Asked Questions

### Q: Does the bot require sending code to third-party cloud APIs?
**A:** No. By default, the bot can operate using **100% offline local LLMs** through Ollama (`qwen2.5-coder`, `llama3`, or `deepseek-coder`). Zero source code ever leaves your internal network perimeter.

### Q: What prevents the bot from committing broken code?
**A:** Every candidate patch must pass two validation tiers before a Pull Request is minted:
1. **AST & Syntax Parsing:** Validates grammar, token boundaries, and indentation.
2. **Ephemeral Docker Verification:** Runs full unit and integration test suites in an isolated Linux container. If any test fails, the patch is automatically rejected or routed to the self-healing retry loop.

### Q: How does the bot handle git merge conflicts with active feature branches?
**A:** The `MergeValidator` tool calculates a 3-way git merge simulation against current `origin/main`. If an upstream change conflicts with the patch lines, the branch is flagged for human review instead of forcing a merge.

---

## 🛠️ Common Troubleshooting Scenarios

### Error: Docker daemon not responding (`is_docker_ready() == False`)
- **Resolution:** Start the Docker service (`systemctl start docker` or launch Docker Desktop). If Docker is not available in your runner, specify `--sandbox-mode local` to utilize process-level subprocess isolation.

### Error: Missing fixed version in SCA report
- **Resolution:** If a package vulnerability has no upstream patch, the `DependencyAgent` marks the finding as requiring manual intervention, preventing unresolvable package bumps.
