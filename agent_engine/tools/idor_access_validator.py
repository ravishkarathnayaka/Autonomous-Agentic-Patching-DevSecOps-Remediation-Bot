"""Security validator for inspecting object access against Insecure Direct Object References (IDOR/BOLA)."""

from typing import Any, Dict, Optional, Set, Tuple


class IdorAccessValidator:
    """Validates authorization constraints between request principals and requested entities (CWE-639)."""

    @classmethod
    def can_access_record(
        cls,
        user_context: Dict[str, Any],
        record: Dict[str, Any],
        owner_field: str = "owner_id",
        tenant_field: Optional[str] = "tenant_id",
        admin_roles: Optional[Set[str]] = None,
    ) -> Tuple[bool, str]:
        """Verify whether user context is authorized to view or mutate record.

        Args:
            user_context: Authenticated principal metadata (e.g. {'user_id': 'u1', 'roles': ['user'], 'tenant_id': 't1'}).
            record: Target database record dict.
            owner_field: Name of the attribute holding the owner ID.
            tenant_field: Optional attribute name for multi-tenant isolation.
            admin_roles: Set of roles that bypass ownership checks.

        Returns:
            Tuple of (authorized: bool, reason: str).
        """
        if not user_context:
            return False, "Unauthenticated request context."

        user_id = str(user_context.get("user_id", ""))
        user_roles = set(user_context.get("roles", []))
        admin_set = admin_roles or {"admin", "superadmin"}

        # Admin bypass
        if user_roles.intersection(admin_set):
            return True, "Access granted via administrative privileges."

        # Tenant isolation check if applicable
        if tenant_field and tenant_field in record:
            user_tenant = str(user_context.get(tenant_field, ""))
            record_tenant = str(record.get(tenant_field, ""))
            if user_tenant != record_tenant:
                return False, f"Cross-tenant access prohibited (user tenant '{user_tenant}' != record tenant '{record_tenant}')."

        # Owner match check
        record_owner = str(record.get(owner_field, ""))
        if user_id and record_owner and user_id == record_owner:
            return True, "Access granted via direct resource ownership."

        return False, f"Access denied: principal '{user_id}' does not own resource '{record.get('id', 'unknown')}'."
