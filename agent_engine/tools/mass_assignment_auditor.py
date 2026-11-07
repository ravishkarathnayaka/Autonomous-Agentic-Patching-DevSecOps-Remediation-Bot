"""Security auditor and parameter filter for mitigating Mass Assignment (CWE-915)."""

from typing import Any, Dict, List, Optional, Set, Tuple


class MassAssignmentAuditor:
    """Audits dictionary inputs and filters allowed fields to prevent Mass Assignment (CWE-915)."""

    DEFAULT_PRIVILEGED_FIELDS = {
        "is_admin", "is_superuser", "is_staff", "role", "roles",
        "permission", "permissions", "group", "groups", "account_id",
        "tenant_id", "owner_id", "password", "password_hash", "credit_balance",
        "wallet_balance", "is_verified", "verified", "internal_notes",
    }

    @classmethod
    def audit_payload(
        cls,
        payload: Dict[str, Any],
        allowed_fields: Optional[List[str]] = None,
        custom_privileged_fields: Optional[Set[str]] = None,
    ) -> Tuple[bool, List[str]]:
        """Audit payload for dangerous unvetted or privilege-escalating keys.

        Args:
            payload: Incoming user request dictionary.
            allowed_fields: Optional strict whitelist of allowed parameter keys.
            custom_privileged_fields: Additional keys deemed privileged.

        Returns:
            Tuple of (is_safe: bool, violations: List[str]).
        """
        violations: List[str] = []
        privileged = cls.DEFAULT_PRIVILEGED_FIELDS.union(custom_privileged_fields or set())
        allowed = set(allowed_fields) if allowed_fields is not None else None

        for key in payload.keys():
            normalized = str(key).lower().strip()
            if normalized in privileged:
                violations.append(f"Privileged attribute '{key}' detected in request payload.")
            elif allowed is not None and key not in allowed:
                violations.append(f"Attribute '{key}' not in permitted field allowlist.")

        is_safe = len(violations) == 0
        return is_safe, violations

    @classmethod
    def filter_allowed_fields(cls, payload: Dict[str, Any], allowed_fields: List[str]) -> Dict[str, Any]:
        """Return a clean dictionary containing strictly the allowed fields from payload."""
        allowed_set = set(allowed_fields)
        return {k: v for k, v in payload.items() if k in allowed_set}
