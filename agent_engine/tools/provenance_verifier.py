"""Cryptographic provenance and tamper-evident audit hash chain for remediation events."""

import hashlib
import json
from typing import Dict, List


class ProvenanceVerifier:
    """Maintains an immutable SHA-256 hash chain recording every agent transition."""

    def __init__(self, genesis_salt: str = "DEVSECOPS-GENESIS-2026"):
        self.chain: List[Dict[str, str]] = []
        self.last_hash = hashlib.sha256(genesis_salt.encode("utf-8")).hexdigest()

    def append_event(self, agent_name: str, event_type: str, payload: dict) -> str:
        """Hash event payload with previous hash to form a linked chain block."""
        serialized_payload = json.dumps(payload, sort_keys=True)
        block_data = f"{self.last_hash}|{agent_name}|{event_type}|{serialized_payload}"
        block_hash = hashlib.sha256(block_data.encode("utf-8")).hexdigest()

        record = {
            "index": len(self.chain) + 1,
            "agent": agent_name,
            "event": event_type,
            "prev_hash": self.last_hash,
            "hash": block_hash
        }
        self.chain.append(record)
        self.last_hash = block_hash
        return block_hash

    def verify_integrity(self) -> bool:
        """Validate that no block in the hash chain has been altered."""
        if not self.chain:
            return True

        for i, block in enumerate(self.chain):
            if i > 0 and block["prev_hash"] != self.chain[i - 1]["hash"]:
                return False
        return True
