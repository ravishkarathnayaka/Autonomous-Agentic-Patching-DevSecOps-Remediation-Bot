# Kubernetes Operator and CRD Architecture Guide

## 1. Executive Overview

To operate natively in cloud-native microservice clusters, the **Autonomous DevSecOps Remediation Bot** provides a Kubernetes Operator controller pattern.

Instead of running as an external CI/CD cron, the operator observes cluster events, listens for admission controller or image scanner alerts, and reconciles `RemediationJob` Custom Resources (CRDs).

---

## 2. Custom Resource Definitions (CRDs)

### `RemediationJob` (v1alpha1)
Defines an autonomous remediation workflow targeting a specific source repository, branch, and scanner alert.

```yaml
apiVersion: devsecops.remediation.io/v1alpha1
kind: RemediationJob
metadata:
  name: fix-cwe-89-payment-service
  namespace: devsecops-system
spec:
  repository:
    url: "git@github.com:organization/payment-service.git"
    baseBranch: "main"
    secretRef:
      name: github-deploy-key
  targetFinding:
    scanner: "semgrep"
    cwe: "CWE-89"
    severity: "CRITICAL"
    filePath: "app/controllers/payment.py"
    lineNumber: 142
  sandboxConfig:
    timeoutSeconds: 180
    memoryLimit: "1Gi"
    cpuLimit: "1000m"
    hermeticIsolation: true
  policyRef:
    name: "fedramp-high-baseline-remediation"
```

---

## 3. Operator Controller Reconciliation Loop

```
┌───────────────────────────────────────┐
│ Kubernetes API Server Watcher         │
│ (Watches RemediationJob CRD events)   │
└──────────────────┬────────────────────┘
                   │
                   ▼
┌───────────────────────────────────────┐
│ Operator Controller Pod               │
│ 1. Spawns ephemeral sandbox Job Pod   │
│ 2. Mounts clone with read-only secrets│
│ 3. Executes PatchAgent & VerifierAgent│
└──────────────────┬────────────────────┘
                   │
                   ▼
┌───────────────────────────────────────┐
│ Hermetic Sandbox Job Pod (Non-Root)   │
│ - networkPolicy: default-deny         │
│ - securityContext.runAsNonRoot: true  │
│ - runs regression pytest suite        │
└──────────────────┬────────────────────┘
                   │
         ┌─────────┴─────────┐
         │ Passed            │ Failed
         ▼                   ▼
┌──────────────────┐┌──────────────────┐
│ Signs Commit and ││ Updates CR Status│
│ Pushes PR Branch ││ with Diagnostics │
└──────────────────┘└──────────────────┘
```

---

## 4. RBAC and Cluster Least Privilege

The operator requires minimal ClusterRole privileges, restricted strictly to Custom Resources and ephemeral Job execution:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: remediation-operator-role
rules:
  - apiGroups: ["devsecops.remediation.io"]
    resources: ["remediationjobs", "remediationjobs/status"]
    verbs: ["get", "list", "watch", "update", "patch"]
  - apiGroups: ["batch"]
    resources: ["jobs"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
```
