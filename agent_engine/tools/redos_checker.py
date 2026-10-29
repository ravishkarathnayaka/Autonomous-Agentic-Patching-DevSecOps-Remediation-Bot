"""Static complexity analyzer to identify Regular Expression Denial of Service (ReDoS / CWE-1333)."""

import re
from typing import Dict, Any


class ReDoSChecker:
    """Analyzes regular expression pattern strings for catastrophic backtracking constructs."""

    # Patterns matching nested quantifiers: (x+)+, (x*)*, (x+)*, (x|y+)+
    NESTED_QUANTIFIER_REGEX = re.compile(
        r"(\((?:[^()]+[+*]|\([^)()]+\))[+*]?\)[+*]|\([^)()]+\|[^)()]+\)[+*])"
    )

    DANGEROUS_REPETITIONS = [
        re.compile(r"\([^\)]*[\+\*][^\)]*\)[\+\*]"),          # (a+)+ or (a*)*
        re.compile(r"\([^\)]*\|[^\)]*[\+\*][^\)]*\)[\+\*]"),  # (a|b+)+
        re.compile(r"(\.\*){2,}"),                            # .*.*
        re.compile(r"(\\d\+){2,}")                            # \d+\d+
    ]

    @classmethod
    def check_regex(cls, pattern: str) -> Dict[str, Any]:
        """Evaluate a regular expression string for catastrophic backtracking vulnerabilities.

        Args:
            pattern: The regular expression string to inspect.

        Returns:
            Dict containing `vulnerable: bool`, `severity: str`, `construct: Optional[str]`, `remediation: str`.
        """
        if not pattern or not isinstance(pattern, str):
            return {"vulnerable": False, "severity": "NONE", "construct": None, "remediation": "Valid"}

        for d_regex in cls.DANGEROUS_REPETITIONS:
            match = d_regex.search(pattern)
            if match:
                construct = match.group(0)
                return {
                    "vulnerable": True,
                    "severity": "HIGH",
                    "construct": construct,
                    "remediation": f"Refactor nested repetition '{construct}' into linear quantifier or atomic group."
                }

        # Check for overlapping character class quantifiers
        overlap_match = re.search(r"(\[[^\]]+\][\+\*]){2,}", pattern)
        if overlap_match:
            return {
                "vulnerable": True,
                "severity": "MEDIUM",
                "construct": overlap_match.group(0),
                "remediation": "Consecutive repeated character classes may cause polynomial backtracking."
            }

        return {
            "vulnerable": False,
            "severity": "NONE",
            "construct": None,
            "remediation": "No catastrophic backtracking patterns detected."
        }
