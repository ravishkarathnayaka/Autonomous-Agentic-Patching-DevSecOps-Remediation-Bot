# AI Remediation Agent Evaluation Metrics & Benchmarks

## 1. Overview

To evaluate autonomous security patching bots, traditional code-generation metrics (such as BLEU or ROUGE) are insufficient. Autonomous DevSecOps remediation requires empirical evaluation spanning syntax correctness, security neutralization, non-regression, and blast radius.

---

## 2. Core Metrics Framework

| Metric Category | Specific KPI | Target Benchmark | Verification Tool |
| :--- | :--- | :--- | :--- |
| **Security Efficacy** | Vulnerability Neutralization Rate (VNR) | > 95% | Rescan with Semgrep / Trivy / DAST |
| **Functional Integrity** | Regression Pass Rate (RPR) | 100% | Unit & integration test execution |
| **Code Hygiene** | AST Blast Radius (Max Lines Changed) | < 25 lines/patch | `blast_radius_analyzer.py` |
| **Speed / MTTR** | Mean Time to Remediate (MTTR) | < 120 seconds | Agent execution telemetry |
| **Convergence** | Verification Loop Iterations | <= 2 retries | `verifier_agent.py` state machine |

---

## 3. Automated Guardrails

1. **AST Diff Verification**: Generated patches must undergo structural AST comparison to ensure no unintended functions or imports are deleted.
2. **Ephemeral Sandboxing**: Verification runs inside isolated subprocess sandboxes with strictly disabled outbound network access.
3. **Consensus Voting**: For high-risk findings, multiple specialized agents (e.g. `VerifierAgent`, `ThreatModelAgent`) must reach quorum before a pull request is created.
