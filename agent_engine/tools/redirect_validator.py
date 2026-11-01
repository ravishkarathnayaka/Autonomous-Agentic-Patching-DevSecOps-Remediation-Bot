"""Security validator for redirect targets and external URLs."""

from typing import Iterable, Optional, Tuple
from urllib.parse import urlparse


class RedirectValidator:
    """Validates destination URLs to eliminate Open Redirect (CWE-601) vulnerabilities."""

    def __init__(self, allowed_domains: Optional[Iterable[str]] = None):
        self.allowed_domains = set(allowed_domains) if allowed_domains else set()

    def validate_redirect_url(self, target_url: str) -> Tuple[bool, str]:
        """Verify whether a target URL is safe for HTTP redirection.

        Args:
            target_url: URL string provided by user/client.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not target_url or not target_url.strip():
            return False, "Empty redirect destination."

        target = target_url.strip()

        # Reject protocol-relative URLs (e.g. //attacker.com)
        if target.startswith("//") or target.startswith("\\\\"):
            return False, "Protocol-relative URL prohibited."

        parsed = urlparse(target)

        # Reject dangerous inline execution schemes
        if parsed.scheme.lower() in ["javascript", "data", "vbscript", "file"]:
            return False, f"Dangerous scheme prohibited: {parsed.scheme}"

        # Relative paths with no scheme and no host are generally safe
        if not parsed.scheme and not parsed.netloc:
            if target.startswith("/"):
                return True, "Safe relative path."
            return False, "Relative path must begin with leading slash ('/')."

        # Validate external network locations against allowlist
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, "Target has scheme but missing valid hostname."

        if self.allowed_domains:
            if hostname in self.allowed_domains or any(hostname.endswith("." + d) for d in self.allowed_domains):
                return True, f"Target hostname '{hostname}' is in domain allowlist."
            return False, f"Destination domain '{hostname}' not in approved allowlist."

        return False, "External absolute redirections prohibited without explicit allowlist."
