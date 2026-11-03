"""Security auditor for JSON Web Tokens (JWT) against RFC 7519 and OWASP JWT Cheat Sheet."""

import base64
import json
import time
from typing import Any, Dict, List, NamedTuple, Tuple


class JwtIssue(NamedTuple):
    severity: str
    issue: str
    recommendation: str


class JwtSecurityAuditor:
    """Audits raw JWT tokens for cryptographic and structural weaknesses."""

    @classmethod
    def audit_token(cls, token: str) -> List[JwtIssue]:
        """Audit an encoded JWT string for structural and cryptographic security defects.

        Args:
            token: Dot-separated JWT string (`header.payload.signature`).

        Returns:
            List of detected JwtIssue findings.
        """
        issues: List[JwtIssue] = []
        if not token or not isinstance(token, str):
            return [JwtIssue("CRITICAL", "Empty or non-string token", "Provide a valid JWT string.")]

        parts = token.strip().split(".")
        if len(parts) != 3:
            return [JwtIssue("CRITICAL", "Invalid JWT format (must have exactly 3 parts)", "Check token structure.")]

        header_b64, payload_b64, signature_b64 = parts

        header = cls._decode_part(header_b64)
        payload = cls._decode_part(payload_b64)

        if not header:
            return [JwtIssue("HIGH", "Failed to parse JWT header as valid JSON", "Ensure base64url encoded JSON.")]
        if not payload:
            return [JwtIssue("HIGH", "Failed to parse JWT payload as valid JSON", "Ensure base64url encoded JSON.")]

        # Check algorithm
        alg = header.get("alg", "").lower()
        if alg == "none":
            issues.append(
                JwtIssue(
                    severity="CRITICAL",
                    issue="JWT algorithm is 'none' (CWE-345)",
                    recommendation="Never accept unsigned tokens; require asymmetric algorithms like RS256 or EdDSA.",
                )
            )

        if not signature_b64:
            issues.append(
                JwtIssue(
                    severity="CRITICAL",
                    issue="JWT signature component is missing",
                    recommendation="Ensure signature is appended and verified on every request.",
                )
            )

        # Check expiration claim
        if "exp" not in payload:
            issues.append(
                JwtIssue(
                    severity="HIGH",
                    issue="JWT payload missing expiration ('exp') claim",
                    recommendation="Include short-lived expiration timestamp (e.g. 15-60 minutes).",
                )
            )
        else:
            try:
                exp_val = int(payload["exp"])
                now = int(time.time())
                if exp_val > now + (30 * 86400):  # More than 30 days
                    issues.append(
                        JwtIssue(
                            severity="MEDIUM",
                            issue=f"JWT expiration time is excessive (> 30 days from now)",
                            recommendation="Reduce token lifetime and use refresh tokens for prolonged sessions.",
                        )
                    )
            except (ValueError, TypeError):
                issues.append(
                    JwtIssue(
                        severity="HIGH",
                        issue="JWT 'exp' claim is not an integer timestamp",
                        recommendation="Set 'exp' to standard Unix epoch integer.",
                    )
                )

        return issues

    @classmethod
    def _decode_part(cls, part: str) -> Dict[str, Any]:
        try:
            # Handle base64url padding
            padded = part + "=" * (-len(part) % 4)
            decoded_bytes = base64.urlsafe_b64decode(padded)
            return json.loads(decoded_bytes.decode("utf-8"))
        except Exception:
            return {}
