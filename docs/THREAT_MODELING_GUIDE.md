# Enterprise Threat Modeling Guide (STRIDE)

This guide documents the enterprise threat model for the **Autonomous Agentic Patching & DevSecOps Remediation Bot**, evaluating security boundaries, threat actors, and mitigations across the patch lifecycle.

---

## 1. System Architecture & Trust Boundaries

```
[ External Scanners ] ---> ( Ingestion Boundary ) ---> [ Orchestrator Engine ]
                                                                 |
                                                                 v
[ Isolated Sandbox ] <--- ( Ephemeral Container API ) <--- [ Patch Generator Agent ]
        |
        v
[ Git Verification / PR Dispatch ] ---> ( Enterprise Version Control )
```

### Trust Boundaries:
1. **Scanner Input Boundary:** Unsanitized third-party reports (SARIF, JSON, XML).
2. **LLM Prompt Boundary:** Potentially malicious code snippets sent to AI models (Prompt Injection).
3. **Execution Sandbox Boundary:** Ephemeral Docker containers running untrusted test suites.
4. **SCM Output Boundary:** Pull request creation and automated branch commits.

---

## 2. STRIDE Threat Analysis

### 2.1 Spoofing
- **Threat:** Threat actor fakes vulnerability scanner output to induce arbitrary code modifications.
- **Mitigation:**
  - Strict schema validation for all 16 supported scanners.
  - Cryptographic verification of scanner payload signatures in CI/CD pipelines.

### 2.2 Tampering
- **Threat:** Malicious patch injects hidden backdoors or exfiltration logic during remediation.
- **Mitigation:**
  - Deterministic AST (Abstract Syntax Tree) difference verification.
  - Strict AST-level bounds checking ensuring changes only touch affected vulnerable lines.
  - Regression testing in hermetic sandbox with disabled networking (`--net none`).

### 2.3 Repudiation
- **Threat:** Disputed automated changes without cryptographic audit trails.
- **Mitigation:**
  - Automated GPG/SSH commit signing with ephemeral CI keys.
  - Immutable audit logs capturing agent prompt, LLM response, diff, and sandbox test exit codes.

### 2.4 Information Disclosure
- **Threat:** Sensitive repository secrets leaked to third-party LLM providers.
- **Mitigation:**
  - Pre-flight secret sanitization with TruffleHog / Gitleaks prior to prompt dispatch.
  - Zero-retention enterprise LLM endpoints (e.g. Claude Enterprise, OpenAI Zero-Retention, Local Ollama).

### 2.5 Denial of Service
- **Threat:** Resource exhaustion via infinite loops or fork bombs in test execution.
- **Mitigation:**
  - Hard timeouts (default 180s per test execution).
  - Cgroup CPU/Memory limits (`--cpus=2`, `--memory=2g`, `--pids-limit=100`).

### 2.6 Elevation of Privilege
- **Threat:** Container escape from ephemeral test sandbox to host Docker daemon.
- **Mitigation:**
  - Docker seccomp security profile (`docker/seccomp-profile.json`).
  - Drop all Linux capabilities (`--cap-drop=ALL`).
  - Read-only root filesystem (`--read-only`).
  - Non-root user execution (`UID 10001:GID 10001`).

---

## 3. Defense-in-Depth Checklist

| Layer | Control | Status |
| :--- | :--- | :--- |
| **Ingestion** | Schema Validator & Autodetect | Active |
| **Agent Prompting** | AST-Constrained System Prompts | Active |
| **Verification** | Ephemeral Docker Sandbox (`--net none`) | Active |
| **Delivery** | Signed Git Branches & Automated Pull Requests | Active |
