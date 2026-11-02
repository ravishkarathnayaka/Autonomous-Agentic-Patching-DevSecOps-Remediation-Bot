"""Security auditor for YAML deserialization safety."""

import re
from typing import List, Tuple


class YamlSafetyAuditor:
    """Audits YAML content and loader configurations to prevent CWE-502 Deserialization vulnerabilities."""

    DANGEROUS_TAG_PATTERNS = [
        re.compile(r"!!python/object"),
        re.compile(r"!!python/module"),
        re.compile(r"!!python/apply"),
        re.compile(r"!!python/name"),
        re.compile(r"tag:yaml\.org,2002:python"),
        re.compile(r"__reduce__"),
        re.compile(r"subprocess\.Popen"),
        re.compile(r"os\.system"),
    ]

    @classmethod
    def audit_yaml_content(cls, content: str) -> Tuple[bool, List[str]]:
        """Audit YAML raw text for known dangerous constructor tags.

        Args:
            content: Raw YAML text content.

        Returns:
            Tuple of (is_safe: bool, violations: List[str]).
        """
        violations: List[str] = []
        if not content:
            return True, []

        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern in cls.DANGEROUS_TAG_PATTERNS:
                if pattern.search(line):
                    violations.append(
                        f"Line {line_num}: Dangerous YAML tag or constructor pattern detected: '{pattern.pattern}'"
                    )

        is_safe = len(violations) == 0
        return is_safe, violations
