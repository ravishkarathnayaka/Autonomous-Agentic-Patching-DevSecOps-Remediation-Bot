"""Security auditor for inspecting HTTP response caching headers against cache poisoning (CWE-444/524)."""

from typing import Dict, List, Tuple


class CacheHeaderAuditor:
    """Audits HTTP headers for secure caching policies and cache poisoning resilience."""

    SENSITIVE_STATUS_CODES = {200, 201, 206}
    UNKEYED_POISON_HEADERS = ["x-forwarded-host", "x-host", "x-original-url", "x-rewrite-url"]

    @classmethod
    def audit_response_headers(
        cls,
        headers: Dict[str, str],
        is_authenticated_or_dynamic: bool = True,
        request_headers: Dict[str, str] = None,
    ) -> Tuple[bool, List[str]]:
        """Audit headers for anti-caching standards on private endpoints.

        Args:
            headers: HTTP response headers dict.
            is_authenticated_or_dynamic: Whether route is private/user-specific.
            request_headers: Optional client request headers to check reflection.

        Returns:
            Tuple of (is_safe: bool, list_of_defects: List[str]).
        """
        defects: List[str] = []
        normalized_resp = {k.lower(): v for k, v in headers.items()}
        cache_control = normalized_resp.get("cache-control", "").lower()
        vary = normalized_resp.get("vary", "").lower()

        if is_authenticated_or_dynamic:
            if not cache_control:
                defects.append("Missing 'Cache-Control' header on authenticated/dynamic route.")
            elif "public" in cache_control:
                defects.append("Dangerous 'Cache-Control: public' directive on authenticated route.")
            elif "no-store" not in cache_control and "no-cache" not in cache_control:
                defects.append("'Cache-Control' does not include 'no-store' or 'no-cache'.")

            if not vary or "cookie" not in vary:
                defects.append("Missing 'Vary: Cookie' header to prevent cross-session cache bleed.")

        if request_headers:
            norm_req = {k.lower(): v for k, v in request_headers.items()}
            for unkeyed in cls.UNKEYED_POISON_HEADERS:
                if unkeyed in norm_req:
                    req_val = norm_req[unkeyed]
                    for resp_k, resp_v in normalized_resp.items():
                        if req_val in resp_v and resp_k not in ["x-forwarded-host", "x-host"]:
                            defects.append(
                                f"Reflected unkeyed header '{unkeyed}' in response header '{resp_k}' "
                                "(potential cache poisoning vector)."
                            )

        is_safe = len(defects) == 0
        return is_safe, defects
