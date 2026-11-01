"""Auditor for HTTP cookie attributes and Set-Cookie directives."""

from typing import Dict, List, Optional, Tuple


class CookieSecurityAuditor:
    """Audits HTTP cookies against enterprise security baselines (CWE-614 / CWE-1004)."""

    @classmethod
    def audit_cookie(
        cls,
        name: str,
        value: str,
        httponly: bool = False,
        secure: bool = False,
        samesite: Optional[str] = None
    ) -> Tuple[bool, List[str]]:
        """Audit cookie attributes against security best practices.

        Args:
            name: Cookie key name.
            value: Cookie token value.
            httponly: True if HttpOnly flag is set.
            secure: True if Secure flag is set.
            samesite: 'Strict', 'Lax', 'None', or None.

        Returns:
            Tuple of (is_compliant: bool, issues: List[str]).
        """
        issues: List[str] = []

        # Check HttpOnly
        if not httponly:
            issues.append(f"Cookie '{name}' is missing HttpOnly flag (vulnerable to XSS theft).")

        # Check Secure
        if not secure:
            issues.append(f"Cookie '{name}' is missing Secure flag (vulnerable to cleartext transport).")

        # Check SameSite
        if not samesite:
            issues.append(f"Cookie '{name}' is missing SameSite attribute (vulnerable to CSRF).")
        elif samesite.lower() not in ["strict", "lax"]:
            issues.append(f"Cookie '{name}' uses weak SameSite setting: {samesite}.")

        # Check prefix validation for sensitive session cookies
        if "session" in name.lower() or "auth" in name.lower():
            if secure and not name.startswith("__Host-") and not name.startswith("__Secure-"):
                issues.append(f"Session cookie '{name}' should consider __Host- or __Secure- prefix.")

        return len(issues) == 0, issues
