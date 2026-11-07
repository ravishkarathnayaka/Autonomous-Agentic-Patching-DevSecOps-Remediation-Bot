"""Security validator for inspecting redirect destinations against Open Redirect (CWE-601)."""

from typing import List, Optional, Tuple
from urllib.parse import urlparse


class OpenRedirectValidator:
    """Validates HTTP redirect target URLs against open redirect vulnerabilities (CWE-601)."""

    PROHIBITED_SCHEMES = {"javascript", "data", "vbscript", "file", "about"}

    @classmethod
    def is_safe_redirect(cls, target_url: str, allowed_hosts: Optional[List[str]] = None) -> bool:
        """Convenience boolean check for safe redirect target."""
        is_safe, _ = cls.validate_target(target_url, allowed_hosts)
        return is_safe

    @classmethod
    def validate_target(cls, target_url: str, allowed_hosts: Optional[List[str]] = None) -> Tuple[bool, str]:
        """Validate destination URL against open redirect breakouts.

        Args:
            target_url: Destination URL string.
            allowed_hosts: Optional whitelist of permitted external hostnames/domains.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not target_url or not target_url.strip():
            return False, "Target URL is empty."

        clean = target_url.strip()

        # Reject protocol-relative URLs (e.g., //evil.com or \\\\evil.com)
        if clean.startswith(("//", "\\\\", "/\\", "\\/")):
            return False, "Protocol-relative URL escape detected."

        # Reject backslash URL obfuscation
        if "\\" in clean:
            return False, "Backslash URL separator prohibited."

        # Reject CRLF injection
        if "\r" in clean or "\n" in clean:
            return False, "CRLF character detected in redirect target."

        try:
            parsed = urlparse(clean)
        except Exception as e:
            return False, f"Malformed URL: {str(e)}"

        if parsed.scheme.lower() in cls.PROHIBITED_SCHEMES:
            return False, f"Prohibited URI scheme '{parsed.scheme}'."

        # Pure relative path redirect is safe (e.g. /dashboard or /profile/settings)
        if not parsed.scheme and not parsed.netloc:
            if clean.startswith("/"):
                return True, "Safe internal relative path redirect."
            return True, "Safe relative path redirect."

        # Absolute URL: require allowed scheme
        if parsed.scheme.lower() not in {"http", "https"}:
            return False, f"Unsupported redirect scheme '{parsed.scheme}'."

        netloc = parsed.netloc.lower()
        # Strip port if present
        host = netloc.split(":")[0]

        if allowed_hosts:
            allowed_set = {h.lower() for h in allowed_hosts}
            if host not in allowed_set:
                return False, f"Target host '{host}' not in permitted redirect allowlist."
            return True, f"Target host '{host}' is in permitted redirect allowlist."

        return False, f"External destination '{host}' not explicitly authorized."
