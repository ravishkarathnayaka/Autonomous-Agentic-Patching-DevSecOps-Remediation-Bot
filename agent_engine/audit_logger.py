"""Tamper-evident cryptographically chained SHA-256 audit ledger for compliance records."""

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from agent_engine.state import RemediationState


class AuditLedger:
    """Maintains an append-only, SHA-256 cryptographically chained audit trail."""

    def __init__(self) -> None:
        self.chain: List[Dict[str, Any]] = []

    def _calculate_hash(self, record_data: Dict[str, Any], previous_hash: str) -> str:
        """Compute SHA-256 digest of record payload concatenated with previous hash."""
        payload = json.dumps(record_data, sort_keys=True) + previous_hash
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def append_record(self, state: RemediationState, actor: str = "Autonomous-Remediation-Bot") -> Dict[str, Any]:
        """Append a new remediation state transition record to the cryptographic chain."""
        previous_hash = self.chain[-1]["current_hash"] if self.chain else "0" * 64

        diff_hash = ""
        if state.patch_diff:
            diff_hash = hashlib.sha256(state.patch_diff.encode("utf-8")).hexdigest()

        record_data = {
            "index": len(self.chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "finding_id": state.finding.id,
            "rule_id": state.finding.rule_id,
            "status": state.status.value,
            "diff_hash": diff_hash,
            "pr_branch": state.pr_branch or "",
            "commit_sha": state.commit_sha or ""
        }

        current_hash = self._calculate_hash(record_data, previous_hash)

        entry = {
            **record_data,
            "previous_hash": previous_hash,
            "current_hash": current_hash
        }
        self.chain.append(entry)
        return entry

    def verify_chain_integrity(self) -> bool:
        """Verify that no records in the audit chain have been tampered with or modified."""
        if not self.chain:
            return True

        for i, entry in enumerate(self.chain):
            expected_prev = "0" * 64 if i == 0 else self.chain[i - 1]["current_hash"]
            if entry["previous_hash"] != expected_prev:
                return False

            data = {
                "index": entry["index"],
                "timestamp": entry["timestamp"],
                "actor": entry["actor"],
                "finding_id": entry["finding_id"],
                "rule_id": entry["rule_id"],
                "status": entry["status"],
                "diff_hash": entry["diff_hash"],
                "pr_branch": entry["pr_branch"],
                "commit_sha": entry["commit_sha"]
            }
            recomputed = self._calculate_hash(data, entry["previous_hash"])
            if recomputed != entry["current_hash"]:
                return False

        return True
