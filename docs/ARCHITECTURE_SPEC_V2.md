# Autonomous DevSecOps Remediation Bot: Architecture Specification v2.0

## Abstract
This document defines the technical specification and inter-agent communication protocols for the **Autonomous Agentic Patching & DevSecOps Remediation Bot 2.0**.

---

## 1. Multi-Agent Finite State Machine

The remediation engine coordinates five autonomous agents through a directed acyclic state graph:

```
[ Ingest Findings ]
        │
        ▼
┌──────────────────┐
│   Triage Agent   │◄── Ingests Semgrep, CodeQL, Snyk, SonarQube, KICS, Horusec
└────────┬─────────┘
         │ Filtered Finding
         ▼
┌──────────────────┐
│   Patch Agent    │◄── Synthesizes minimal diff with AST context & temperature annealing
└────────┬─────────┘
         │ Unified Diff
         ▼
┌──────────────────┐
│  Verifier Agent  │◄── Runs tests in zero-trust Docker container
└────────┬─────────┘
         │
    ┌────┴────────────────────────┐
    │ Passed                      │ Failed
    ▼                             ▼
┌──────────────────┐      ┌──────────────────┐
│     PR Agent     │      │ Self-Healing Loop│──► (Feeds diagnostics back to Patch Agent)
└──────────────────┘      └──────────────────┘
```

---

## 2. Supported Scanners Matrix (v2.0)

| Scanner Name | Modality | Output Parser | Supported Standards |
|---|---|---|---|
| **Semgrep** | SAST | `semgrep_json` | OWASP Top 10, CWE Top 25 |
| **GitHub CodeQL** | SAST | `codeql_sarif` | SARIF 2.1.0, GitHub Security |
| **Trivy** | SCA | `trivy_json` | CVE, NVD, Alpine, Debian OS |
| **Snyk** | SCA | `snyk_json` | Snyk Advisory Database, SemVer |
| **SonarQube** | SAST | `sonarqube_json` | Clean Code, Sonar Security |
| **KICS** | IaC | `kics_json` | Terraform, Kubernetes, Dockerfile |
| **Horusec** | SAST | `horusec_json` | Multi-Language Static Analysis |
| **GitGuardian** | Secrets | `gitguardian_json` | API Keys, Cloud Credentials |
| **Brakeman** | SAST | `brakeman_json` | Ruby on Rails Security |
| **Checkov** | IaC | `checkov_json` | CIS Benchmarks, Cloud Misconfigs |
