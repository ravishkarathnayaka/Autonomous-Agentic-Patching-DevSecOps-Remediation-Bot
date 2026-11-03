"""Security validator and escaper for RFC 4515 LDAP search filters."""

import re
from typing import Tuple


class LdapFilterValidator:
    """Validates and escapes strings intended for LDAP search filters to eliminate CWE-90."""

    DANGEROUS_INJECTION_PATTERNS = [
        re.compile(r"\)\s*\(\|"),          # )( | breakout
        re.compile(r"\)\s*\(\&"),          # )( & breakout
        re.compile(r"\*\)\s*\("),          # *) ( wildcard breakout
        re.compile(r"\x00"),               # Null byte injection
    ]

    @classmethod
    def is_safe_filter_value(cls, value: str) -> Tuple[bool, str]:
        """Verify whether a value is safe to use inside an LDAP filter without escaping.

        Args:
            value: User input string.

        Returns:
            Tuple of (is_safe: bool, reason: str).
        """
        if not isinstance(value, str):
            return False, "Input value must be a string."

        if not value:
            return True, "Empty string is safe."

        for pattern in cls.DANGEROUS_INJECTION_PATTERNS:
            if pattern.search(value):
                return False, "Input contains LDAP filter logical breakout patterns."

        # Verify parentheses balance
        if value.count("(") != value.count(")"):
            return False, "Unbalanced parentheses detected in LDAP filter parameter."

        return True, "Safe LDAP filter value."

    @classmethod
    def escape_filter_value(cls, value: str) -> str:
        """Escape special characters per RFC 4515 into 2-digit hex representations.

        Args:
            value: Input string to escape.

        Returns:
            Sanitized RFC 4515 string.
        """
        if not value:
            return ""

        escaped = []
        for char in value:
            if char == "\\":
                escaped.append("\\5c")
            elif char == "*":
                escaped.append("\\2a")
            elif char == "(":
                escaped.append("\\28")
            elif char == ")":
                escaped.append("\\29")
            elif char == "\x00":
                escaped.append("\\00")
            else:
                escaped.append(char)
        return "".join(escaped)
