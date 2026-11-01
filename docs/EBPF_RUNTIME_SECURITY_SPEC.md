# eBPF Runtime Security and Automated Kernel Guardrails Specification

## 1. Executive Summary

Static code patching operates prior to deployment, but zero-day exploits and runtime container escapes bypass static analysis. By coupling the **Autonomous Remediation Bot** with **Extended Berkeley Packet Filter (eBPF)** runtime instrumentation (via **Cilium** and **Tetragon**), teams achieve continuous runtime observability, behavioral blocking, and closed-loop kernel patching.

---

## 2. eBPF Integration Topology

```
┌────────────────────────────────────────────────────────┐
│ Kubernetes Node (Linux Kernel Layer)                   │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Tetragon eBPF Kernel Probes                      │  │
│  │ - Intercepts `sys_execve`, `sys_connect`         │  │
│  │ - Detects namespace escapes & unauthorized spawn │  │
│  └────────────────────────┬─────────────────────────┘  │
│                           │ Kernel Event Alert         │
│                           ▼                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Autonomous DevSecOps Remediation Bot Engine      │  │
│  │ 1. Triages runtime process tree & binary hash    │  │
│  │ 2. Synthesizes declarative TracingPolicy CRD     │  │
│  │ 3. Generates in-source AST defensive interceptor │  │
│  └────────────────────────┬─────────────────────────┘  │
│                           │                            │
│                           ▼                            │
│  ┌──────────────────────────────────────────────────┐  │
│  │ Enforcement Actions                              │  │
│  │ - Hot-drops rogue process with SIGKILL           │  │
│  │ - Applies ephemeral Pod NetworkPolicy block      │  │
│  └──────────────────────────────────────────────────┘  │
│                                                        │
└────────────────────────────────────────────────────────┘
```

---

## 3. Declarative Tetragon TracingPolicy Generation

For exploited vulnerabilities involving unexpected process execution, the remediation engine automatically emits an immutable Tetragon `TracingPolicy` to block the executable at the kernel level:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-container-reverse-shell
  namespace: kube-system
spec:
  kprobes:
    - call: "sys_execve"
      syscall: true
      args:
        - index: 0
          type: "string"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Prefix"
              values:
                - "/bin/sh"
                - "/bin/bash"
                - "/usr/bin/nc"
          matchActions:
            - action: Sigkill
```

---

## 4. Closed-Loop Remediation Sequence

1. **Kernel Event Telemetry**: eBPF captures untrusted execution inside a production container.
2. **Dynamic Quorum & Virtual Patch**: Bot applies a kernel drop rule in $< 100$ milliseconds.
3. **Root Cause Source Code Patch**: The bot traces the callsite back to the vulnerable endpoint (e.g. CWE-78 in `target_repo/app.py`), synthesizes an AST patch, verifies it in the hermetic Docker sandbox, and opens a GitHub Pull Request.
