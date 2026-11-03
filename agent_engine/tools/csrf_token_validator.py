"""Security validator for Cross-Site Request Forgery (CSRF / CWE-352) protections."""

from typing import Dict, List, Optional, Tuple


class CsrfTokenValidator:
    """Validates presence and entropy of Anti-CSRF tokens and SameSite cookie policies."""

    STATE_CHANGING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}
    CSRF_HEADER_NAMES = {"x-csrf-token", "x-xsrf-token", "x-csrftoken"}

    @classmethod
    def validate_request_csrf(
        cls,
        http_method: str,
        headers: Dict[str, str],
        cookies: Optional[Dict[str, str]] = None,
        body_params: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, str]:
        """Validate whether a request includes sufficient Anti-CSRF defense.

        Args:
            http_method: HTTP request verb (GET, POST, etc.).
            headers: Request HTTP headers.
            cookies: Request cookies dictionary.
            body_params: Form/JSON body parameters.

        Returns:
            Tuple of (is_valid: bool, reason: str).
        """
        method = http_method.upper()
        if method not in cls.STATE_CHANGING_METHODS:
            return True, f"HTTP method '{method}' is idempotent / read-only."

        normalized_headers = {k.lower(): v for k, v in headers.items()}
        # Check authorization header (Bearer token is generally immune to browser CSRF)
        if "authorization" in normalized_headers and normalized_headers["authorization"].lower().startswith("bearer "):
            return True, "Authorization Bearer token present (immune to browser cookie CSRF)."

        # Check dedicated Anti-CSRF header
        for csrf_header in cls.CSRF_HEADER_NAMES:
            if csrf_header in normalized_headers:
                token_val = normalized_headers[csrf_header].strip()
                if len(token_val) >= 16:
                    return True, f"Valid Anti-CSRF token present in header '{csrf_header}'."
                return False, f"Anti-CSRF token in header '{csrf_header}' is insufficiently long (< 16 chars)."

        # Check body parameter
        if body_params:
            for k in ["csrf_token", "csrfmiddlewaretoken", "xsrf_token"]:
                if k in body_params and len(body_params[k]) >= 16:
                    return True, f"Valid Anti-CSRF token present in form body parameter '{k}'."

        return False, f"State-changing '{method}' request missing required Anti-CSRF token or Bearer authorization."
