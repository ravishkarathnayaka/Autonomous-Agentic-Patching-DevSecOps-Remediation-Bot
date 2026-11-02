# CISA Secure Software Development Attestation Implementation Guide

## 1. Regulatory Context

In response to White House Executive Order 14028 and OMB Memoranda M-22-18 / M-23-16, federal agencies require software producers to attest that their products are developed in accordance with the NIST SP 800-218 Secure Software Development Framework (SSDF).

This guide details how the **Autonomous DevSecOps Remediation Bot** operationalizes automated compliance across all four core pillars of the CISA Common Form.

---

## 2. The Four Pillars of Compliance

### Pillar 1: Secure Software Development Environment
- **Cryptographic Version Control**: All commits signed via GPG or SSH keys.
- **Hermetic Build Sandboxes**: Build environments execute without ambient internet access and with dropped Linux capabilities (`CAP_DROP_ALL`).
- **Separation of Duties**: Automated remediation agents act as unprivileged contributors submitting pull requests subject to policy gate checks.

### Pillar 2: Trusted Third-Party Components
- **Dependency Transparency**: CycloneDX 1.5 and SPDX 2.3 SBOM generation integrated into every build pipeline.
- **Automated Vulnerability Mitigation**: SCA scanning using Grype, Snyk, and Black Duck with automated AST pull-request generation.
- **Package Integrity**: All upstream packages verified against SHA-256 hash digests and SLSA Level 3 attestations.

### Pillar 3: Vulnerability Identification & Remediation
- **Continuous Static & Dynamic Analysis**: Automated SAST (Semgrep, SonarQube, CodeQL) and DAST (OWASP ZAP) executed on every branch commit.
- **SLA Enforcement**: Zero-critical vulnerability mandate within 24 hours of disclosure.
- **Automated Regression Verification**: Remediation patches must pass unit and contract tests before PR submission.

### Pillar 4: Vulnerability Disclosure & VEX
- **Responsible Disclosure Protocol**: Standard `security.txt` and vulnerability disclosure policy (VDP) maintained.
- **Machine-Readable VEX**: OpenVEX advisories published to downstream consumers.

---

## 3. Automated Attestation Checklist

| Check ID | Description | Bot Automated Control | Status |
| :--- | :--- | :--- | :--- |
| `CISA-P1-01` | Multi-factor authentication enforced on code repos | OIDC Github Actions / Workload Identity | Enforced |
| `CISA-P2-01` | Validated SBOM published per release | CycloneDX Generator (`cyclonedx_generator.py`) | Enforced |
| `CISA-P3-01` | Automated static analysis (SAST) executed | Multi-scanner engine (40+ scanners) | Enforced |
| `CISA-P3-02` | Remediation within defined SLAs | Automated patch synthesizing agents | Enforced |
| `CISA-P4-01` | VEX advisories published for dependencies | VEX Generator (`vex_generator.py`) | Enforced |
