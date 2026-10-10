import pytest
from agent_engine.audit_logger import AuditLedger
from agent_engine.state import Finding, RemediationState, RemediationStatus, SeverityLevel


def test_audit_ledger_chain_and_tampering():
    finding = Finding(
        id="f-audit-1",
        scanner="semgrep",
        rule_id="CWE-89",
        title="SQLi",
        description="SQL injection finding",
        severity=SeverityLevel.HIGH,
        file_path="app.py"
    )
    state = RemediationState(
        finding=finding,
        target_repo_path="./target_repo",
        status=RemediationStatus.VERIFIED,
        patch_diff="--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n- bad\n+ good",
        commit_sha="11223344"
    )

    ledger = AuditLedger()
    entry1 = ledger.append_record(state)
    assert entry1["index"] == 0
    assert entry1["previous_hash"] == "0" * 64

    # Second entry
    state.status = RemediationStatus.PR_READY
    state.pr_branch = "fix/sqli-patch"
    entry2 = ledger.append_record(state)
    assert entry2["index"] == 1
    assert entry2["previous_hash"] == entry1["current_hash"]

    # Verify chain integrity
    assert ledger.verify_chain_integrity() is True

    # Tamper with an entry
    ledger.chain[0]["status"] = "TAMPERED_STATUS"
    assert ledger.verify_chain_integrity() is False
