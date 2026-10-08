# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

We take the security of this project and the safety of autonomous agent systems seriously. If you discover a security vulnerability in this repository (especially regarding sandbox escapes, command injections, or malicious diff execution), please report it responsibly.

### How to Report

1. **Do NOT open a public GitHub Issue.**
2. Send an email with full vulnerability details to the project maintainers:
   - **Email:** `security@autonomous-devsecops.local` (or file a private GitHub Security Advisory).
3. Include the following details in your report:
   - A descriptive summary of the vulnerability
   - Affected component(s) (e.g., `agent_engine/tools/sandbox_executor.py`, `agent_engine/agents/patch_agent.py`)
   - Step-by-step reproduction instructions or a minimal Proof of Concept (PoC)
   - Impact assessment (e.g., container breakout, arbitrary host execution)
   - Any suggested remediations or mitigations

---

## Response Timeline

- **Acknowledgment:** Within 48 hours of initial report.
- **Triage & Assessment:** Within 5 business days.
- **Remediation & Patch Release:** Coordinated with the reporter, typically within 14–30 days depending on severity.

---

## Core Security Controls in this Project

This project enforces strict defense-in-depth measures when handling untrusted candidate code:
- **Ephemeral Docker Sandboxes:** Code testing executes with `network_disabled=True`, dropping all capabilities (`cap_drop=['ALL']`).
- **Resource Constraints:** Strict memory limits (`512MB`) and CPU quotas (`cpu_quota=100000`) prevent denial-of-service loops.
- **AST Pre-Validation:** Untrusted patches are pre-screened before container invocation.
- **Read-Only Volume Mounts:** Where applicable, system assets are mounted with `mode='ro'`.

Thank you for helping keep the open-source DevSecOps ecosystem secure!
