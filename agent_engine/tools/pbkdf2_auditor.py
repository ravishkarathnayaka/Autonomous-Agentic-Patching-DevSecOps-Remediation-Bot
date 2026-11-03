"""Security auditor for Password-Based Key Derivation Functions against NIST SP 800-132."""

from typing import List, NamedTuple


class KdfAuditFinding(NamedTuple):
    parameter: str
    severity: str
    issue: str
    recommendation: str


class Pbkdf2ParameterAuditor:
    """Audits PBKDF2 and KDF invocation parameters to prevent CWE-916 and CWE-326."""

    MIN_PBKDF2_SHA256_ITERATIONS = 600000
    MIN_SALT_BYTES = 16
    WEAK_HASH_ALGORITHMS = {"md5", "sha1", "ripemd160"}

    @classmethod
    def audit_parameters(
        cls,
        hash_name: str,
        iterations: int,
        salt: bytes,
    ) -> List[KdfAuditFinding]:
        """Audit KDF parameters against NIST SP 800-132 standards.

        Args:
            hash_name: Underlying hash function (e.g. 'sha256', 'sha512', 'md5').
            iterations: Number of derivation loop iterations.
            salt: Salt bytes passed to KDF.

        Returns:
            List of detected KdfAuditFinding issues.
        """
        findings: List[KdfAuditFinding] = []
        clean_hash = hash_name.lower().replace("-", "")

        # Check hash algorithm
        if clean_hash in cls.WEAK_HASH_ALGORITHMS:
            findings.append(
                KdfAuditFinding(
                    parameter="hash_name",
                    severity="CRITICAL",
                    issue=f"Weak cryptographic hash algorithm used: '{hash_name}'",
                    recommendation="Use SHA-256, SHA-384, or SHA-512 for HMAC pseudorandom function.",
                )
            )

        # Check iteration count
        if iterations < cls.MIN_PBKDF2_SHA256_ITERATIONS:
            findings.append(
                KdfAuditFinding(
                    parameter="iterations",
                    severity="HIGH" if iterations < 10000 else "MEDIUM",
                    issue=f"Inadequate iteration count ({iterations}) leaves KDF susceptible to brute force.",
                    recommendation=f"Set iterations to at least {cls.MIN_PBKDF2_SHA256_ITERATIONS} per NIST SP 800-132.",
                )
            )

        # Check salt length and randomness
        if not salt or len(salt) < cls.MIN_SALT_BYTES:
            findings.append(
                KdfAuditFinding(
                    parameter="salt",
                    severity="HIGH",
                    issue=f"Salt length ({len(salt) if salt else 0} bytes) is below minimum required 128 bits (16 bytes).",
                    recommendation="Generate salt using `os.urandom(16)` or `secrets.token_bytes(16)`.",
                )
            )

        return findings
