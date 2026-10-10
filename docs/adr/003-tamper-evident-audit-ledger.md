# ADR 003: Tamper-Evident SHA-256 Audit Ledger

## Status
Accepted

## Context
SOC2 Type II, ISO 27001, and FedRAMP compliance frameworks require non-repudiation and immutable change history for automated systems modifying code.

## Decision
We implemented a cryptographically chained SHA-256 Merkle ledger (`AuditLedger`) recording state transitions, actor identification, diff hashes, and verification verdicts with forward integrity checking.

## Consequences
- **Positive**: Satisfies enterprise regulatory compliance and provides indisputable forensic audit trails.
- **Negative**: Adds lightweight SHA-256 computation overhead upon every state transition.
