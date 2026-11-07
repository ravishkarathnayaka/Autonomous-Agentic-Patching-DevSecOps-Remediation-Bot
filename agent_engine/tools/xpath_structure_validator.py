"""Security validator for inspecting strings destined for XPath queries against CWE-643."""

import re
from typing import List, Tuple


class XpathStructureValidator:
    """Validates literal values against XPath injection breakout characters (CWE-643)."""

    PROHIBITED_CHARS = ["'", '"', "[", "]", "/", "\\", "$", "(", ")", ";", "|"]
    PROHIBITED_TOKENS_REGEX = re.compile(r"\b(or|and|not|contains|starts-with|count|true|false)\b", re.IGNORECASE)

    @classmethod
    def is_safe_literal(cls, value: str) -> bool:
        """Convenience boolean check for safe XPath literal value."""
        is_safe, _ = cls.validate_literal(value)
        return is_safe

    @classmethod
    def validate_literal(cls, value: str) -> Tuple[bool, List[str]]:
        """Verify whether input string is safe to embed inside an XPath predicate.

        Args:
            value: User-provided input string.

        Returns:
            Tuple of (is_safe: bool, list_of_defects: List[str]).
        """
        defects: List[str] = []

        if not value or not value.strip():
            return False, ["Value is empty."]

        for ch in cls.PROHIBITED_CHARS:
            if ch in value:
                defects.append(f"Prohibited delimiter character '{ch}' detected.")

        matches = cls.PROHIBITED_TOKENS_REGEX.findall(value)
        if matches:
            unique_tokens = sorted(set(m.lower() for m in matches))
            defects.append(f"XPath boolean / function keyword(s) detected: {', '.join(unique_tokens)}.")

        is_safe = len(defects) == 0
        return is_safe, defects
