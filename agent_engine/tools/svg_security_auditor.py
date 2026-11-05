"""Security auditor for inspecting SVG content against XXE and stored XSS."""

import re
from typing import List, Tuple


class SvgSecurityAuditor:
    """Audits SVG payloads for XML External Entity (XXE) and Stored XSS vectors (CWE-611 / CWE-79)."""

    DANGEROUS_PATTERNS = [
        (re.compile(r"<!DOCTYPE[^>]*>", re.IGNORECASE), "DOCTYPE declaration is prohibited (CWE-611)"),
        (re.compile(r"<!ENTITY[^>]*>", re.IGNORECASE), "ENTITY declaration is prohibited (CWE-611)"),
        (re.compile(r"SYSTEM\s+[\"'][^\"']+[\"']", re.IGNORECASE), "SYSTEM external entity prohibited (CWE-611)"),
        (re.compile(r"<script[\s>]", re.IGNORECASE), "Embedded <script> tag detected (CWE-79)"),
        (re.compile(r"on\w+\s*=", re.IGNORECASE), "Inline event handler (e.g. onload/onerror) detected (CWE-79)"),
        (re.compile(r"javascript\s*:", re.IGNORECASE), "javascript: pseudo-protocol detected (CWE-79)"),
        (re.compile(r"<foreignObject[\s>]", re.IGNORECASE), "<foreignObject> embedding detected"),
    ]

    @classmethod
    def audit_svg(cls, svg_content: str) -> Tuple[bool, List[str]]:
        """Scan SVG string for dangerous XXE and script injection constructs.

        Args:
            svg_content: Raw SVG content string.

        Returns:
            Tuple of (is_safe: bool, list_of_violations: List[str]).
        """
        violations: List[str] = []

        if not svg_content or not svg_content.strip():
            return False, ["SVG content is empty."]

        for regex, msg in cls.DANGEROUS_PATTERNS:
            if regex.search(svg_content):
                violations.append(msg)

        is_safe = len(violations) == 0
        return is_safe, violations
