# Enterprise Incident Response Runbook: Autonomous DevSecOps Remediation

## 1. Overview and Operational Scope

This runbook defines operational procedures for triaging, remediating, and reviewing security vulnerabilities detected across enterprise CI/CD pipelines and production runtime environments using the Autonomous Agentic Remediation Bot.

---

## 2. Severity Classification Matrix & SLA Targets

| Severity Tier | CVSS Score Range | Automated SLA | Notification Channels | Escalation Path |
|---|---|---|---|---|
| **P0 - Critical** | 9.0 - 10.0 | < 12 Hours | PagerDuty (Urgent), Slack `#sec-sev0`, Teams | CISO, Engineering VP, Lead DevSecOps |
| **P1 - High** | 7.0 - 8.9 | < 24 Hours | Slack `#sec-high-alerts`, Teams | Security Engineering Lead |
| **P2 - Medium** | 4.0 - 6.9 | < 72 Hours | Slack `#sec-remediation-bot`, Jira | Component Tech Lead |
| **P3 - Low** | 0.1 - 3.9 | < 168 Hours (7 Days) | Weekly Digest / GitHub PR Dashboard | Repository Codeowners |

---

## 3. Incident Lifecycle Phases

```
┌────────────────────┐
│ 1. Ingestion       │ Ingest SARIF/JSON from 24+ supported scanner formats
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 2. Triage & Dedupe │ Calculate CVSS 3.1 vector; deduplicate across scanners
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 3. Agent Synthesis │ PatchAgent generates AST-validated candidate diff
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 4. Verification    │ Run regression suite in hermetic Docker container
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 5. PR & Attestation│ Sign commit with Ed25519; generate SPDX SBOM & Cosign proof
└─────────┬──────────┘
          ▼
┌────────────────────┐
│ 6. Rollback / Audit│ Automated revert on post-deploy canary metric anomaly
└────────────────────┘
```

---

## 4. Break-Glass Human Override

In emergencies where autonomous patching must be paused or a candidate patch aborted:

### 1. Disable Autonomous Merging Globally
```bash
python -m cli.main config set --auto-merge=false
```

### 2. Kill Active Agent Remediation Task
```bash
python -m cli.main task terminate --task-id <TASK_ID> --reason "Operator override"
```

### 3. Immediate Git Rollback
```bash
git checkout main
git revert --no-edit <COMMIT_HASH>
git push origin main
```

---

## 5. Post-Remediation Verification & Audit Logging

Every remediation operation automatically archives:
1. **Raw Scanner Finding**: Preserved in `.system_generated/logs/`.
2. **Unified Diff Artifact**: Stored with cryptographic SHA-256 hash.
3. **Container Sandbox Logs**: stdout and stderr streams of regression test runs.
4. **SPDX 2.3 SBOM**: Linux Foundation compliant bill of materials capturing upgraded components.
5. **Cosign Attestation**: Keyless OIDC signature confirming pipeline integrity.
