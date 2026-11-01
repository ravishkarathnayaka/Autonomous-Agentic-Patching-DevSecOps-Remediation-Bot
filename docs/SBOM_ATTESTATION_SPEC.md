# Software Bill of Materials (SBOM) Ingestion & Attestation Specification

## 1. Executive Overview

Software supply chain attacks frequently exploit opaque transitive dependencies. The **Autonomous DevSecOps Remediation Bot** implements an enterprise standard for generating, verifying, and cryptographically attesting Software Bill of Materials (SBOMs) conforming to both **Linux Foundation SPDX 2.3** and **OWASP CycloneDX 1.5** schemas.

---

## 2. Dual-Standard SBOM Architecture

```
┌────────────────────────────────────────────────────────┐
│ Repository Dependencies (requirements.txt / package.json)
└───────────────────────────┬────────────────────────────┘
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Autonomous Dependency Analyzer                         │
│ - Resolves canonical Package URLs (PURLs)              │
│ - Enriches with Google OSV & NVD Advisory metadata     │
└─────────────┬────────────────────────────┬─────────────┘
              │                            │
              ▼                            ▼
┌───────────────────────────┐┌───────────────────────────┐
│ Linux Foundation SPDX 2.3 ││ OWASP CycloneDX 1.5       │
│ JSON Document Model       ││ Component Graph Model     │
└─────────────┬─────────────┘└─────────────┬─────────────┘
              │                            │
              └─────────────┬──────────────┘
                            ▼
┌────────────────────────────────────────────────────────┐
│ Cryptographic Attestation via Sigstore Cosign          │
│ In-toto Predicate Generation & Keyless OIDC Signing    │
└────────────────────────────────────────────────────────┘
```

---

## 3. Package URL (PURL) Resolution Standard

Every component represented in generated SBOM documents MUST be assigned an RFC-compliant Package URL (PURL):

- **PyPI Packages**: `pkg:pypi/<package-name>@<version>`
- **NPM Modules**: `pkg:npm/<package-name>@<version>`
- **Golang Modules**: `pkg:golang/<module-path>@<version>`
- **Docker Base Images**: `pkg:docker/<image-name>@sha256:<digest>`

---

## 4. Verification and Attestation Protocol

1. **Pre-Patch SBOM Snapshot**: Prior to applying any remediation patch, an initial SBOM is captured and hashed with SHA-256.
2. **Post-Patch SBOM Snapshot**: Following sandbox verification, a revised SBOM is computed reflecting bumped package versions.
3. **Cryptographic In-Toto Attestation**: The diff between the pre-patch and post-patch SBOMs is enveloped in an in-toto attestation statement signed with the bot's private Ed25519 signing key or Sigstore OIDC token.
