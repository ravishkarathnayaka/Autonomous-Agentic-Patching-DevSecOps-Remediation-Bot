"""Security auditor for HTTP response headers against OWASP Secure Headers Project."""

from typing import Dict, List, NamedTuple


class HeaderFinding(NamedTuple):
    header: str
    severity: str
    issue: str
    recommendation: str


class SecurityHeaderAuditor:
    """Audits HTTP headers to ensure compliance with OWASP Secure Headers recommendations."""

    RECOMMENDED_HEADERS: Dict[str, Dict[str, str]] = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "recommendation": "max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "recommendation": "default-src 'self'; frame-ancestors 'none'; object-src 'none'",
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "recommendation": "nosniff",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "recommendation": "DENY",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "recommendation": "strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "LOW",
            "recommendation": "camera=(), microphone=(), geolocation=()",
        },
    }

    @classmethod
    def audit_headers(cls, headers: Dict[str, str]) -> List[HeaderFinding]:
        """Audit a dictionary of HTTP headers for missing or insecure values.

        Args:
            headers: Case-insensitive or normalized dict of response headers.

        Returns:
            List of HeaderFinding instances for missing or inadequate headers.
        """
        normalized_headers = {k.lower(): (k, v) for k, v in headers.items()}
        findings: List[HeaderFinding] = []

        for rec_header, info in cls.RECOMMENDED_HEADERS.items():
            header_lower = rec_header.lower()
            if header_lower not in normalized_headers:
                findings.append(
                    HeaderFinding(
                        header=rec_header,
                        severity=info["severity"],
                        issue=f"Missing recommended security header: '{rec_header}'",
                        recommendation=f"Add header '{rec_header}: {info['recommendation']}'",
                    )
                )
            else:
                actual_name, actual_val = normalized_headers[header_lower]
                val_clean = actual_val.strip().lower()
                if header_lower == "x-content-type-options" and "nosniff" not in val_clean:
                    findings.append(
                        HeaderFinding(
                            header=rec_header,
                            severity="MEDIUM",
                            issue=f"X-Content-Type-Options header has weak value: '{actual_val}'",
                            recommendation="Set value to 'nosniff'",
                        )
                    )
                elif header_lower == "x-frame-options" and val_clean not in ["deny", "sameorigin"]:
                    findings.append(
                        HeaderFinding(
                            header=rec_header,
                            severity="MEDIUM",
                            issue=f"X-Frame-Options header has weak value: '{actual_val}'",
                            recommendation="Set value to 'DENY' or 'SAMEORIGIN'",
                        )
                    )

        return findings
