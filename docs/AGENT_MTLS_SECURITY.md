# Zero-Trust Agent-to-Agent mTLS & SPIFFE Identity Specification

## 1. Architectural Scope

In multi-agent remediation architectures, specialized agents (e.g., triage agents, patch generation agents, sandbox executors, and PR automators) communicate over distributed RPC channels. To prevent unauthorized agent impersonation and tampering, all inter-agent communications enforce **Mutual TLS (mTLS)** and **SPIFFE / SPIRE cryptographic workload identity**.

---

## 2. SPIFFE Identity Naming Model

Every agent is issued an X.509 SVID (SPIFFE Verifiable Identity Document) signed by an internal root certificate authority.

| Agent Role | SPIFFE ID Format |
| :--- | :--- |
| Triage Agent | `spiffe://devsecops.internal/ns/agents/sa/triage-agent` |
| Remediation Patch Agent | `spiffe://devsecops.internal/ns/agents/sa/patch-agent` |
| Hermetic Sandbox Executor | `spiffe://devsecops.internal/ns/agents/sa/sandbox-executor` |
| Pull Request Dispatcher | `spiffe://devsecops.internal/ns/agents/sa/pr-dispatcher` |

---

## 3. Communication Security Controls

- **Cipher Suite Enforcement**: TLS 1.3 exclusively (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
- **Short-Lived SVIDs**: Workload certificates expire every 1 hour, requiring automated in-memory rotation via SPIRE Workload API.
- **Authorization Policies**: SPIFFE ID-based RBAC prevents unauthorized agents from requesting PR creation or accessing source repository write tokens.
