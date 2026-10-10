# OWASP Top 10 Enterprise Agentic Remediation Matrix

This document defines how the **Autonomous DevSecOps Remediation Bot** addresses each category of the **OWASP Top 10 Web Application Security Risks**.

---

## Remediation Coverage Matrix

| OWASP Category | Target CWEs | Detection Scanners | Agent Workflow | Autonomous Patch Pattern | Verification Strategy |
|:---|:---|:---|:---|:---|:---|
| **A01: Broken Access Control** | CWE-22 (Path Traversal)<br>CWE-639 (IDOR) | Semgrep, Bandit, Horusec, SonarQube | Triage -> Patch -> Verifier | Canonical path resolution (`Path.resolve`), scope DB queries by tenant/owner ID | Unit test path traversal boundary vectors (`../../etc/passwd`) |
| **A02: Cryptographic Failures** | CWE-327 (Broken Crypto)<br>CWE-311 (Missing Encryption) | Semgrep, Bandit, Checkov, KICS | Triage -> Dual-Review -> Verifier | Upgrade MD5/SHA1 to SHA-256; enforce AES-256-GCM / TLS 1.3 | Re-scan cryptographic algorithms with AST validator |
| **A03: Injection** | CWE-89 (SQL Injection)<br>CWE-78 (Command Injection)<br>CWE-79 (XSS) | Semgrep, Bandit, Horusec, OWASP ZAP | Triage -> Patch -> Verifier | Parameterized prepared statements; `subprocess.run(shell=False)` with argument lists; context-aware HTML escaping | Execute functional regression suite and exploit fuzz payloads in sandbox |
| **A04: Insecure Design** | CWE-250 (Execution with Unnecessary Privileges) | Checkov, KICS, Trivy | Triage -> Patch -> Verifier | Add `USER nonroot` to Dockerfile; configure `securityContext.runAsNonRoot: true` in K8s | Container runtime verification & healthcheck probe |
| **A05: Security Misconfiguration** | CWE-16 (Configuration Error)<br>CWE-284 (Improper Access Control) | Checkov, KICS, Semgrep | Triage -> Patch -> Verifier | Enforce S3 block public access; restrict security group CIDRs from `0.0.0.0/0` to VPN bastions | IaC re-scan with Checkov & KICS parsers |
| **A06: Vulnerable & Outdated Components** | CVE-2023-32681, CVE-2022-40897, Transitive SCA | Trivy, Snyk, Grype, Pip-Audit | Triage -> DependencyBumper -> Verifier | Parse `requirements.txt` / `package.json`, bump to minimal patched semantic version | Sandbox dependency reinstall and test suite verification |
| **A07: Identification & Authentication Failures** | CWE-798 (Hardcoded Credentials)<br>CWE-287 (Improper Authentication) | Gitleaks, TruffleHog | SecretRemediationAgent -> Verifier | Redact secrets from source; replace with `os.getenv()` or vault lookups | Gitleaks staged re-scan verifying zero active secret entropy |
| **A08: Software & Data Integrity Failures** | CWE-502 (Deserialization)<br>SLSA Level 3 | Semgrep, Bandit, Snyk | Triage -> Patch -> Verifier | Replace `pickle.loads` / `yaml.load` with `json.loads` or `yaml.safe_load` | Sandbox functional regression testing with serialized test objects |
| **A09: Security Logging & Monitoring Failures** | CWE-778 (Insufficient Logging) | SonarQube, Semgrep | Triage -> Explainer -> Verifier | Inject structured JSON logging and audit trail hooks | Verification test inspecting log output formatting |
| **A10: Server-Side Request Forgery (SSRF)** | CWE-918 (SSRF) | Semgrep, Horusec, OWASP ZAP | Triage -> Patch -> Verifier | Domain/hostname allowlisting; block loopback (127.0.0.1) and cloud metadata (169.254.169.254) | Network egress unit test validating forbidden destination rejection |

---

## Closed-Loop Verification Guarantee

1. **Ephemeral Sandboxing**: Every patch is applied inside an isolated container (Docker or unprivileged local subprocess) with CPU and memory quotas.
2. **Deterministic Regressions**: If unit tests break or the security re-scan detects that the vulnerability persists, the feedback error trace is fed back into the Patch Agent.
3. **Dual Sign-Off Gateways**: Under PCI-DSS and SOC2 profiles, sensitive cryptographic modules and hardcoded secret patches require human peer review prior to branch merge.
