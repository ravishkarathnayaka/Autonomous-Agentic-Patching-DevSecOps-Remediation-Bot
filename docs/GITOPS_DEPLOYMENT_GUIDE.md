# GitOps Continuous Remediation Deployment Guide

## 1. Introduction

GitOps treats the Git repository as the single source of truth for declared infrastructure and application state. By integrating the **Autonomous DevSecOps Remediation Bot** with GitOps controllers (such as **Argo CD** or **Flux v2**), teams can achieve fully automated, closed-loop vulnerability detection, code repair, and continuous deployment.

---

## 2. GitOps Workflow Topology

```
   ┌────────────────────────────────────────┐
   │ Vulnerability Scanner (Trivy / KICS)   │
   └───────────────────┬────────────────────┘
                       │ Webhook Trigger
                       ▼
   ┌────────────────────────────────────────┐
   │ Autonomous Remediation Bot Engine      │
   │ 1. Triages CVE & generates fix branch  │
   │ 2. Runs verification in Sandbox        │
   │ 3. Signs commit with Ed25519/GPG       │
   └───────────────────┬────────────────────┘
                       │ Opens PR / Merges to Main
                       ▼
   ┌────────────────────────────────────────┐
   │ Git Repository (Single Source of Truth)│
   └───────────────────┬────────────────────┘
                       │ Git Sync / Webhook
                       ▼
   ┌────────────────────────────────────────┐
   │ Argo CD / Flux Controller              │
   │ Detects declarative manifest drift     │
   └───────────────────┬────────────────────┘
                       │ Canary Sync (Argo Rollouts)
                       ▼
   ┌────────────────────────────────────────┐
   │ Kubernetes Production Cluster Workload │
   └────────────────────────────────────────┘
```

---

## 3. Argo CD Application Configuration

To allow the remediation bot to update manifests autonomously, configure an Argo CD `Application` resource with automated synchronization and self-healing:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: secured-payment-service
  namespace: argocd
spec:
  project: default
  source:
    repoURL: 'https://github.com/organization/target-repo.git'
    targetRevision: main
    path: k8s/production
  destination:
    server: 'https://kubernetes.default.svc'
    namespace: production
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
      - ApplyOutOfSyncOnly=true
    retry:
      limit: 5
      backoff:
        duration: 5s
        factor: 2
        maxDuration: 3m
```

---

## 4. Cryptographic Commit Signature Verification

GitOps controllers must reject unsigned commits originating from untrusted pipelines. Configure branch protection and GitOps verification:

1. **Bot Commit Signing Key**: Ensure the bot's GPG or SSH Ed25519 signing key is registered in GitHub and marked as `Verified`.
2. **Branch Protection Policy**: Require signed commits (`Require signed commits: true`) on `main` and release branches.
3. **Flux Source Controller Verification**:
```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: GitRepository
metadata:
  name: secured-repo
  namespace: flux-system
spec:
  interval: 1m
  url: https://github.com/organization/target-repo.git
  ref:
    branch: main
  verify:
    mode: head
    secretRef:
      name: gpg-public-keys
```

---

## 5. Automated Canary Verification & Rollback

Using **Argo Rollouts**, the remediated application is progressively routed traffic (e.g. 5%, 20%, 50%, 100%) while Prometheus monitors HTTP 5xx error rates and latency:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: payment-service-rollout
spec:
  replicas: 10
  strategy:
    canary:
      analysis:
        templates:
          - templateName: error-rate-check
        args:
          - name: service-name
            value: payment-service
      steps:
        - setWeight: 10
        - pause: { duration: 5m }
        - setWeight: 50
        - pause: { duration: 10m }
```

If the error rate exceeds 0.5% during the canary window, Argo Rollouts immediately halts the release and rolls back to the previous stable revision, notifying the remediation engine via webhook.
