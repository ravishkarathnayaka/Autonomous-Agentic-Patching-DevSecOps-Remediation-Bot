# Supply Chain Security: SLSA Level 3 Attestation & Cosign Signing Guide

## 1. Executive Summary

Supply chain Levels for Software Artifacts (**SLSA**) is a security framework initiated by Google and OpenSSF to prevent tampering, improve integrity, and secure software packages and infrastructure. The **Autonomous DevSecOps Remediation Bot** satisfies **SLSA Level 3** build integrity requirements through hermetic build isolation, cryptographic provenance generation, and keyless container signing using **Sigstore Cosign**.

---

## 2. SLSA Level 3 Requirements Mapping

| SLSA L3 Requirement | Remediation Bot Implementation | Verification Mechanism |
|---|---|---|
| **Hermetic Build Environment** | Ephemeral Docker container with zero network access (`network_disabled=True`). | Docker engine runtime inspection. |
| **Isolated Build Platform** | Dedicated GitHub Actions / K8s runner pods ephemeral per task. | Ephemeral container lifecycle. |
| **Cryptographic Provenance** | `SLSAProvenanceGenerator` emits in-toto statement with SHA-256 digest. | JSON Schema & SHA validation. |
| **Non-Falsifiable Attestation**| Signed via Sigstore Cosign keyless OIDC identity token. | Public Rekor transparency log. |
| **Complete Materials Record** | Full tree of dependencies, commit hashes, and base image digests. | SPDX 2.3 & CycloneDX 1.5 SBOM. |

---

## 3. Cosign Keyless Verification Command

To verify that a remediated container image or build artifact was produced legitimately by the autonomous remediation bot and has not been altered:

```bash
# Verify container image signature against GitHub OIDC workflow identity
cosign verify \
  --certificate-identity "https://github.com/ravishkarathnayaka/Autonomous-Agentic-Patching-DevSecOps-Remediation-Bot/.github/workflows/remediation.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/organization/remediated-app:latest
```

---

## 4. Admission Controller Enforcement via Kyverno

In Kubernetes production clusters, unsigned or non-SLSA compliant images are blocked at admission time via Kyverno policy:

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-slsa-attestation
spec:
  validationFailureAction: Enforce
  rules:
    - name: check-cosign-signature
      match:
        resources:
          kinds:
            - Pod
      verifyImages:
        - imageReferences:
            - "ghcr.io/organization/*"
          attestations:
            - predicateType: https://slsa.dev/provenance/v0.2
              conditions:
                - all:
                    - key: "{{ builder.id }}"
                      operator: Equals
                      value: "https://github.com/actions/runner@v3"
```
