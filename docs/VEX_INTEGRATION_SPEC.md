# Vulnerability Exploitability eXchange (VEX) Integration Specification

## 1. Executive Summary

As enterprise software systems adopt automated vulnerability remediation, conveying the exploitability status of dependencies and internal modules is essential to prevent alert fatigue. The **Autonomous DevSecOps Remediation Bot** provides native generation and publication of **OpenVEX (v0.2.0)** and **CSAF (Common Security Advisory Framework v2.0)** documents, conveying machine-readable assertions on whether detected vulnerabilities affect running systems.

---

## 2. VEX Architecture & Lifecycle

```
┌────────────────────────────────────────────────────────┐
│ Scanner Findings Ingestion (SARIF / JSON / CycloneDX)  │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Remediation & Sandbox Verification Engine               │
│ - Verified Patched -> Status: "fixed"                  │
│ - Unreachable Code -> Status: "not_affected"           │
│ - Triage Pending   -> Status: "under_investigation"    │
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ OpenVEX Generator (agent_engine/tools/vex_generator.py)│
│ - Canonical PURL referencing                           │
│ - Cryptographic Sigstore cosign signing                │
└────────────────────────────────────────────────────────┘
```

---

## 3. Supported Status Classifications

| VEX Status | Description | Action Statement |
| :--- | :--- | :--- |
| `not_affected` | Vulnerability is present in code/dependency but unreachable or neutralized by compensating controls. | No user action required; compiler flags or sandbox boundaries prevent exploitability. |
| `affected` | Vulnerability is active and exploitable in production workloads. | Immediate remediation patch generation scheduled. |
| `fixed` | Vulnerability was successfully remediated and verified in the ephemeral hermetic sandbox. | Deploy generated pull request patch to production environment. |
| `under_investigation` | Scanner detected finding; root-cause analysis and automated test generation in progress. | Monitoring telemetry and triaging AST impact. |

---

## 4. OpenVEX Document Schema Example

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "urn:openvex:corp.devsecops:advisory-2026-1102",
  "author": "Autonomous DevSecOps Remediation Engine",
  "role": "Autonomous Security Remediation Engine",
  "timestamp": "2026-11-02T23:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-32681",
        "description": "Unintended leak of Proxy-Authorization header in requests library"
      },
      "products": ["pkg:pypi/requests@2.31.0"],
      "status": "fixed",
      "action_statement": "Remediated via autonomous patch and verified against unit test suite."
    }
  ]
}
```

---

## 5. Security & Verification

All generated VEX documents are cryptographically signed using Sigstore Cosign keyless signatures and published alongside SBOM artifacts in the enterprise container and OCI artifact registry.
