# ADR 004: Declarative DevSecOps Policy Governance Engine

## Status
Accepted

## Context
Organizations enforce strict boundaries regarding which vulnerabilities can be autonomously patched versus those requiring manual peer review (e.g. PCI-DSS Requirement 6.4 for cryptography).

## Decision
We implemented `RemediationPolicyEngine` reading declarative YAML policies that specify CVSS score thresholds, allowed/banned CWE sets, path exclusion patterns, and compliance profiles (PCI-DSS, SOC2, ISO 27001).

## Consequences
- **Positive**: Complete policy governance control for security officers without requiring code modifications.
- **Negative**: Misconfigured policies may block valid remediation attempts.
