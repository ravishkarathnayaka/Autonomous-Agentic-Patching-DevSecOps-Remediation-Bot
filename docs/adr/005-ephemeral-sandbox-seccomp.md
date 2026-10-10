# ADR 005: Ephemeral Sandbox Isolation via Seccomp and OCI Profiles

## Status
Accepted

## Context
Running arbitrary target repository test suites in response to AI-generated code could expose the host runner to malicious code execution or container breakouts.

## Decision
We enforce strict Seccomp filters (`seccomp-profile.json`) and unprivileged user permissions inside `sandbox.Dockerfile`, disabling syscalls including `ptrace`, `sys_chroot`, and raw kernel socket access.

## Consequences
- **Positive**: Hardens sandbox against privilege escalation and lateral network movement.
- **Negative**: Test suites requiring raw socket operations or root capabilities must be isolated in secondary environments.
