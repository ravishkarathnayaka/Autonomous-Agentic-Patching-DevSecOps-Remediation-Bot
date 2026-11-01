"""Security evaluator for Jinja2 template strings and SSTI payloads."""

import re
from typing import List, Tuple


class JinjaSandboxEvaluator:
    """Evaluates template strings against dangerous SSTI introspection vectors."""

    FORBIDDEN_ATTRIBUTES = [
        r"__class__",
        r"__mro__",
        r"__subclasses__",
        r"__builtins__",
        r"__globals__",
        r"__import__",
        r"__init__",
        r"__base__",
        r"lipsum",
        r"cycler",
        r"joiner"
    ]

    @classmethod
    def evaluate_template_safety(cls, template_str: str) -> Tuple[bool, List[str]]:
        """Check if a template string contains dangerous AST attributes or sandbox escape sequences.

        Args:
            template_str: Raw template string to audit.

        Returns:
            Tuple of (is_safe: bool, list_of_violations: List[str]).
        """
        violations: List[str] = []

        for pattern in cls.FORBIDDEN_ATTRIBUTES:
            if re.search(r"\b" + pattern + r"\b", template_str, re.IGNORECASE):
                violations.append(f"Forbidden introspection attribute detected: {pattern}")

        # Check for unescaped expression delimiters matching dangerous execution
        if re.search(r"\{\{.*(?:\.__|\['__|\[\"__).*\}\}", template_str):
            violations.append("Attempted object traversal inside expression delimiter.")

        return len(violations) == 0, violations
