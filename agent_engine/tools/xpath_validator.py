"""Security validator for XPath queries and expression sanitization."""

import re
from typing import Tuple


class XPathValidator:
    """Validates XPath expressions and dynamic user arguments against XPath Injection (CWE-643)."""

    DANGEROUS_PATTERNS = [
        re.compile(r"['\"][ ]*(?:or|and)[ ]*['\"]", re.IGNORECASE),
        re.compile(r"['\"][ ]*or[ ]+1[ ]*=[ ]*1", re.IGNORECASE),
        re.compile(r"//[a-zA-Z0-9_\-*]+\[.*?\]"),  # nested injection attempts
        re.compile(r"(?:count|string-length|name|local-name)\s*\(", re.IGNORECASE),
    ]

    DISALLOWED_AXES = [
        "ancestor",
        "ancestor-or-self",
        "parent",
        "following",
        "preceding",
    ]

    @classmethod
    def is_safe_literal(cls, value: str) -> Tuple[bool, str]:
        """Verify whether a value is safe to use as a string literal parameter in XPath.

        Args:
            value: The string literal input to validate.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not isinstance(value, str):
            return False, "Input value must be a string."

        if "'" in value and '"' in value:
            return False, "Input contains both single and double quotes, vulnerable to injection escape."

        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern.search(value):
                return False, f"Input contains potentially malicious XPath boolean injection syntax."

        return True, "Safe XPath literal."

    @classmethod
    def sanitize_literal(cls, value: str) -> str:
        """Sanitize a string literal for safe inclusion in an XPath query using concat() if needed.

        Args:
            value: The string to escape.

        Returns:
            Escaped XPath string expression.
        """
        if "'" not in value:
            return f"'{value}'"
        if '"' not in value:
            return f'"{value}"'
        parts = value.split("'")
        quoted_parts = [f"'{p}'" for p in parts]
        return f"concat({', \"\'\", '.join(quoted_parts)})"
