"""Security auditor for detecting catastrophic backtracking and ReDoS vulnerabilities in regexes."""

import re
from typing import List, Tuple


class RegexComplexityAuditor:
    """Audits regular expressions for dangerous exponential or polynomial backtracking (CWE-1333)."""

    DANGEROUS_CONSTRUCTS = [
        (re.compile(r"\([^)]*[\+\*][^)]*\)[\+\*]"), "Nested quantifiers (e.g. `(a+)+` or `(a*)*`) induce exponential backtracking."),
        (re.compile(r"\(\[[^\]]+\][\+\*]\)[\+\*]"), "Nested character class repetition induces catastrophic backtracking."),
        (re.compile(r"\([^\|]+\|[^\|]+\)[\+\*]"), "Alternation with repetition inside group can lead to polynomial/exponential branching."),
        (re.compile(r"(.)\1\{50,\}"), "Excessive static repetition bounds may exceed match stack limits."),
    ]

    @classmethod
    def is_safe_pattern(cls, pattern: str) -> bool:
        """Convenience method returning True if pattern has no detected ReDoS hazards."""
        is_safe, _ = cls.audit_pattern(pattern)
        return is_safe

    @classmethod
    def audit_pattern(cls, pattern: str) -> Tuple[bool, List[str]]:
        """Analyze regular expression string for catastrophic backtracking hazards.

        Args:
            pattern: Regular expression pattern string.

        Returns:
            Tuple of (is_safe: bool, warnings: List[str]).
        """
        warnings: List[str] = []

        if not pattern or not pattern.strip():
            return True, ["Empty pattern is safe."]

        # Check syntactic validity first
        try:
            re.compile(pattern)
        except re.error as e:
            return False, [f"Invalid regular expression syntax: {str(e)}"]

        # Check for catastrophic backtracking structural signatures
        for hazard_regex, desc in cls.DANGEROUS_CONSTRUCTS:
            if hazard_regex.search(pattern):
                warnings.append(desc)

        is_safe = len(warnings) == 0
        return is_safe, warnings
