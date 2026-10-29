# Multi-Agent Consensus and Voting Protocol Specification

## 1. Executive Overview

In autonomous security remediation, relying on a single large language model (LLM) or standalone heuristic agent introduces single points of failure, hallucinations, and risky patch proposals. The **Autonomous DevSecOps Remediation Bot** implements an enterprise-grade **Multi-Agent Consensus and Voting Protocol (MACVP)**.

Under this protocol, no patch is committed to a pull request or production branch without achieving formal cryptographic and heuristic quorum across specialized autonomous sub-agents.

---

## 2. Agent Voting Council Topology

The council consists of five distinct domain-specialized agents:

```
                  ┌───────────────────────────────┐
                  │    Ingested Vulnerability     │
                  └──────────────┬────────────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ Patch Synthesis Engine│
                     └───────────┬───────────┘
                                 │ Candidate Patch
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
│  Security Audit  │    │ Regression Guard │    │ Performance & SLA│
│      Agent       │    │      Agent       │    │      Agent       │
└────────┬─────────┘    └────────┬─────────┘    └────────┬─────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 ▼
                    ┌─────────────────────────┐
                    │ Consensus Voting Engine │
                    └────────────┬────────────┘
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
        [ Quorum Achieved (>=80%) ]   [ Quorum Rejected ]
                   │                           │
                   ▼                           ▼
          Generate Pull Request       Self-Healing AST Loop
```

### Council Members:
1. **Security Audit Agent (Weight: 35%)**: Evaluates whether the generated patch completely remediates the target CWE without introducing secondary vulnerabilities or OWASP regressions.
2. **Regression Guard Agent (Weight: 30%)**: Analyzes AST changes against test suite baselines, ensuring no breaking changes to public APIs, function signatures, or expected exceptions.
3. **Hermetic Sandbox Verifier (Weight: 20%)**: Executes test suites inside isolated Docker containers; enforces zero non-zero exit codes.
4. **Performance & SLA Agent (Weight: 10%)**: Compares execution time, memory complexity, and algorithmic efficiency (e.g. ReDoS prevention).
5. **Supply Chain Validator (Weight: 5%)**: Audits newly introduced dependencies against Google OSV, SLSA provenance, and SPDX SBOM records.

---

## 3. Mathematical Quorum Formulation

Each council member evaluates candidate patch $P$ and assigns a normalized confidence score $S_i(P) \in [0.0, 1.0]$ and a binary veto flag $V_i(P) \in \{0, 1\}$.

The aggregated consensus score $C(P)$ is defined as:

$$C(P) = \left( \sum_{i=1}^n w_i \cdot S_i(P) \right) \times \prod_{i=1}^n (1 - V_i(P))$$

Where:
- $w_i$ is the static weighting coefficient of agent $i$, such that $\sum_{i=1}^n w_i = 1.0$.
- Any single agent asserting $V_i(P) = 1$ (hard veto) forces $C(P) = 0$, immediately aborting the candidate patch.

### Approval Thresholds:
- **Automatic Merge Quorum**: $C(P) \ge 0.90$ with zero test failures and full hermetic sandbox passage.
- **Pull Request Creation**: $0.75 \le C(P) < 0.90$, flagged with comprehensive agent review notes.
- **Patch Rejection & Self-Healing Feedback**: $C(P) < 0.75$, returning AST error diagnostics to the patch generation prompt.

---

## 4. Hard Veto Triggers

An agent MUST assert a hard veto ($V_i = 1$) under the following non-negotiable conditions:
- **Syntax or Compile Errors**: Code failing compilation or Python AST parsing.
- **Test Suite Failures**: Any existing regression test producing an assertion error or unexpected exception.
- **Introduction of CWE-798**: Hardcoded credentials, private keys, or tokens detected in the diff.
- **Egress Violation**: Attempted socket connections outside approved localhost loopbacks during sandbox verification.
- **Destructive Deletions**: Deletion of more than 40% of the enclosing function without equivalent semantic substitution.
