# LLM Hallucination Prevention & AST Proof Verification Guide

## 1. Executive Summary

Generative AI models are inherently probabilistic and susceptible to hallucinations—such as inventing nonexistent library methods, modifying unrelated source files, or dropping crucial business logic. The **Autonomous DevSecOps Remediation Bot** applies formal **Abstract Syntax Tree (AST) Proof Verification** to deterministically bound model behavior and reject defective patches prior to execution.

---

## 2. AST Verification Pipeline

```
┌────────────────────────────────────────┐
│ Candidate Unified Git Diff from LLM    │
└──────────────────┬─────────────────────┘
                   │
                   ▼
┌────────────────────────────────────────┐
│ Stage 1: Pre-Flight Syntax Parse       │
│ Run `ast.parse()` on patched file      │
│ - Abort immediately on SyntaxError     │
└──────────────────┬─────────────────────┘
                   │ Syntax Valid
                   ▼
┌────────────────────────────────────────┐
│ Stage 2: Scope Invariance Verification │
│ - Verify ONLY target function modified │
│ - Ensure enclosing classes preserved   │
│ - Zero changes to unaffected endpoints │
└──────────────────┬─────────────────────┘
                   │ Scope Intact
                   ▼
┌────────────────────────────────────────┐
│ Stage 3: Signature & Type Equivalence  │
│ - Compare parameter count and types    │
│ - Verify return type annotations match │
└──────────────────┬─────────────────────┘
                   │ Equivalence Confirmed
                   ▼
┌────────────────────────────────────────┐
│ Stage 4: Hermetic Docker Sandbox Run   │
│ Execute pytest regression test suite   │
└────────────────────────────────────────┘
```

---

## 3. Strict Semantic Guardrails

1. **Non-Destructive Deletion Boundary**: If the synthesized patch deletes more than 35% of existing AST nodes within the target block without replacement, it is automatically rejected as a destructive hallucination.
2. **Import Whitelist Validation**: Any newly introduced import statement is validated against standard library modules or approved dependencies present in `requirements.txt`.
3. **AST Node Count Differential**: The net change in AST node count $|\Delta N_{nodes}|$ must not exceed 60 nodes for a single vulnerability remediation.
