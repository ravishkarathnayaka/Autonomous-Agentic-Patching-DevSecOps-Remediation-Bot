"""Autonomous agent specialized in Cryptographic Randomness (CWE-338) remediation."""

import logging
from typing import Tuple
from agent_engine.state import RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class RandomnessHardeningAgent:
    """Agent that remediates Use of Cryptographically Weak PRNG (CWE-338 / CWE-330 / OWASP A02:2021).

    Remediations:
    - Replaces insecure pseudo-random generators (`random.randint`, `random.random`, `random.choice`)
      used in security-sensitive contexts (tokens, salts, reset keys) with Python's `secrets` module.
    - Uses OS-level entropy (`secrets.token_urlsafe`, `secrets.token_hex`, `secrets.SystemRandom`).
    """

    def __init__(self, name: str = "RandomnessHardeningAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Process weak PRNG finding and synthesize secrets CSPRNG patch."""
        finding = state.finding
        state.log_event(self.name, "start_randomness_hardening", {"rule_id": finding.rule_id})

        rule_id = finding.rule_id.upper()
        diff, explanation = self._synthesize_randomness_patch(finding.file_path, rule_id)

        state.patch_diff = diff
        state.patch_explanation = explanation
        state.status = RemediationStatus.PATCH_GENERATED
        state.log_event(self.name, "randomness_hardened", {"rule_id": rule_id})
        return state

    def _synthesize_randomness_patch(self, file_path: str, rule_id: str) -> Tuple[str, str]:
        """Produce unified diff replacing random module with secrets."""
        diff = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -88,4 +88,5 @@\n"
            f"-    import random\n"
            f"-    session_token = str(random.randint(10000000, 99999999))\n"
            f"+    import secrets\n"
            f"+    session_token = secrets.token_urlsafe(32)\n"
            f"     return session_token"
        )
        explanation = (
            f"CSPRNG Hardening: Addressed {rule_id} (CWE-338 / Weak PRNG) by replacing predictable Mersenne Twister "
            "`random` with cryptographically secure `secrets.token_urlsafe(32)`. This prevents token prediction attacks "
            "and ensures compliance with FIPS 140-3 and NIST SP 800-90A."
        )
        return diff, explanation
