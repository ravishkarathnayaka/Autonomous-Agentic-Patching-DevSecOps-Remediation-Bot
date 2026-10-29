"""Network egress security validator to defend against Server-Side Request Forgery (CWE-918)."""

import ipaddress
import socket
from typing import Dict, Any
from urllib.parse import urlparse


class SSRFValidator:
    """Validates URLs and resolved IP addresses against private networks and metadata endpoints."""

    BLOCKED_IPS = {
        "169.254.169.254",  # AWS/GCP/Azure instance metadata service (IMDS)
        "fd00:ec2::254",     # AWS IMDS IPv6
    }

    ALLOWED_SCHEMES = {"http", "https"}

    @classmethod
    def validate_url(cls, url: str) -> Dict[str, Any]:
        """Validate whether a URL is safe to query from backend services.

        Args:
            url: Outbound URL string.

        Returns:
            Dict containing `safe: bool`, `ip: Optional[str]`, `reason: str`.
        """
        if not url or not isinstance(url, str):
            return {"safe": False, "ip": None, "reason": "Empty or invalid URL supplied."}

        try:
            parsed = urlparse(url)
        except Exception as e:
            return {"safe": False, "ip": None, "reason": f"Malformed URL: {e}"}

        scheme = (parsed.scheme or "").lower()
        if scheme not in cls.ALLOWED_SCHEMES:
            return {
                "safe": False,
                "ip": None,
                "reason": f"Prohibited URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."
            }

        hostname = parsed.hostname
        if not hostname:
            return {"safe": False, "ip": None, "reason": "No hostname found in URL."}

        if hostname.lower() in {"localhost", "metadata.google.internal"}:
            return {"safe": False, "ip": None, "reason": "Explicit loopback or cloud metadata domain name."}

        # Resolve IP
        try:
            resolved_ip_str = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip_str)
        except (socket.gaierror, ValueError) as e:
            return {"safe": False, "ip": None, "reason": f"DNS resolution failed for hostname '{hostname}': {e}"}

        if resolved_ip_str in cls.BLOCKED_IPS:
            return {
                "safe": False,
                "ip": resolved_ip_str,
                "reason": "Target IP addresses cloud instance metadata endpoint."
            }

        if ip_obj.is_loopback:
            return {
                "safe": False,
                "ip": resolved_ip_str,
                "reason": f"Target IP {resolved_ip_str} is a loopback interface."
            }

        if ip_obj.is_private:
            return {
                "safe": False,
                "ip": resolved_ip_str,
                "reason": f"Target IP {resolved_ip_str} belongs to RFC 1918 private network."
            }

        if ip_obj.is_link_local:
            return {
                "safe": False,
                "ip": resolved_ip_str,
                "reason": f"Target IP {resolved_ip_str} is link-local."
            }

        if ip_obj.is_reserved or ip_obj.is_multicast:
            return {
                "safe": False,
                "ip": resolved_ip_str,
                "reason": f"Target IP {resolved_ip_str} is reserved/multicast."
            }

        return {
            "safe": True,
            "ip": resolved_ip_str,
            "reason": "URL destination is public and passes SSRF egress validation."
        }
