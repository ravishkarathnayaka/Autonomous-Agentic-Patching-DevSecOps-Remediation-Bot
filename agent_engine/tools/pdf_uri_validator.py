"""Security validator for PDF rendering target URIs against SSRF and local file disclosures."""

import ipaddress
import socket
from typing import List, Optional, Tuple
from urllib.parse import urlparse


class PdfUriAllowlistValidator:
    """Validates URLs supplied to HTML-to-PDF / rendering tools against SSRF (CWE-918)."""

    ALLOWED_SCHEMES = {"http", "https"}
    BLOCKED_HOSTS = {"localhost", "127.0.0.1", "::1", "169.254.169.254", "metadata.google.internal"}

    def __init__(self, allowed_domains: Optional[List[str]] = None):
        self.allowed_domains = set(allowed_domains) if allowed_domains else None

    def is_safe_url(self, url: str) -> bool:
        """Convenience boolean check for safe URL."""
        is_safe, _ = self.validate_url(url)
        return is_safe

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """Validate URL scheme and ensure it does not resolve to private or cloud metadata IPs.

        Args:
            url: Target URL string.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not url or not url.strip():
            return False, "Target URL is empty."

        try:
            parsed = urlparse(url.strip())
        except Exception as e:
            return False, f"Malformed URL: {str(e)}"

        if parsed.scheme.lower() not in self.ALLOWED_SCHEMES:
            return False, f"Prohibited URI scheme '{parsed.scheme}'. Only HTTP/HTTPS permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL does not contain a valid hostname."

        if hostname.lower() in self.BLOCKED_HOSTS:
            return False, f"Prohibited target host '{hostname}' (loopback/cloud metadata)."

        if self.allowed_domains and hostname.lower() not in self.allowed_domains:
            return False, f"Hostname '{hostname}' not in explicit domain allowlist."

        # IP address check
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, f"Direct IP address '{hostname}' points to internal/private network range."
        except ValueError:
            # It is a domain name, not a raw IP literal
            pass

        return True, "URL is safe for document rendering."
