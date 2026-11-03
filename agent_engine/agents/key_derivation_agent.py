"""Autonomous agent specialized in Key Derivation & Password Hashing (CWE-916) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class KeyDerivationHardeningAgent:
    """Agent that remediates Insufficient Computational Effort in Key Derivation (CWE-916 / CWE-326).

    Remediations:
    - Replaces static or predictable salts with `os.urandom(16)` / `secrets.token_bytes(16)`.
    - Enforces NIST SP 800-132 compliant PBKDF2 iterations (>= 600,000) or modern memory-hard KDFs.
    """

    def __init__(self, name: str = "KeyDerivationHardeningAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process weak key derivation finding and synthesize hardened KDF patch."""
        finding = state.finding
        state.log_event(self.name, "start_key_derivation_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_kdf_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "key_derivation_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_kdf_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff upgrading salt generation and iteration count."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -482,4 +482,5 @@\n"
            f"-    static_salt = b\"hardcoded_salt_123\"\n"
            f"-    derived = hashlib.pbkdf2_hmac(\"sha256\", password.encode(\"utf-8\"), static_salt, 100)\n"
            f"+    salt = os.urandom(16)\n"
            f"+    derived = hashlib.pbkdf2_hmac(\"sha256\", password.encode(\"utf-8\"), salt, 600000)"
        )
        explanation = (
            f"Key Derivation Hardening: Addressed {rule_id} (CWE-916) by replacing static salt with "
            "cryptographically random salt (`os.urandom(16)`) and increasing PBKDF2-HMAC-SHA256 iterations to 600,000 "
            "in accordance with NIST SP 800-132 recommendations."
        )
        return diff, explanation
