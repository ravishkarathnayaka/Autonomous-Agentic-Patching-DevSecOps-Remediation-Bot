# Zero-Trust Container Sandboxing & Security Safeguards

This technical whitepaper details the isolation barriers and defense-in-depth mechanisms employed by the remediation bot when compiling and testing untrusted AI-generated patches.

---

## 🛡️ Core Security Invariants

When evaluating third-party security patches, the execution runtime must treat code as **potentially hostile**. The bot enforces four non-negotiable invariants:

### 1. Complete Network Isolation (`--network=none`)
- The container is provisioned with zero external network connectivity.
- Loopback interface only (`127.0.0.1`).
- Eliminates risk of data exfiltration, reverse shell connections, or malicious dependency fetching.

### 2. Dropped Linux Capabilities (`--cap-drop=ALL`)
- Containers discard all POSIX capabilities.
- Prevents raw socket creation (`CAP_NET_RAW`), kernel module manipulation (`CAP_SYS_MODULE`), and chroot tampering.

### 3. Custom Seccomp Profile (`docker/seccomp-profile.json`)
- Restricts dangerous Linux system calls at the kernel boundary:
  - Blocks `ptrace`, `bpf`, `process_vm_readv`, `kexec_load`, and filesystem mounting (`mount`, `umount`).

### 4. Ephemeral Workspace Teardown
- Containers are spawned per-vulnerability attempt and destroyed immediately upon test completion.
- Filesystem changes never persist outside the isolated volume sandbox.
