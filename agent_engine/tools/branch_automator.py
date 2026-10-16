"""Git branch naming and automated remediation release lifecycle utility."""

import re
import uuid


def generate_remediation_branch_name(cwe_id: str, title: str, prefix: str = "remediate") -> str:
    """Generate standardized git branch name for vulnerability patch PR.

    Args:
        cwe_id: CWE or CVE identifier (e.g. CWE-89 or CVE-2023-30861).
        title: Short vulnerability description.
        prefix: Branch prefix.

    Returns:
        Kebab-case normalized branch name (e.g. 'remediate/cwe-89-sql-injection-a1b2').
    """
    clean_id = cwe_id.lower().replace("_", "-")
    clean_title = re.sub(r"[^a-zA-Z0-9]+", "-", title.lower()).strip("-")
    slug = clean_title[:30].rstrip("-")
    short_hash = uuid.uuid4().hex[:6]

    return f"{prefix}/{clean_id}-{slug}-{short_hash}"


def validate_branch_name(branch_name: str) -> bool:
    """Validate that branch name complies with git ref specifications."""
    if not branch_name or " " in branch_name or ".." in branch_name:
        return False
    if branch_name.startswith("/") or branch_name.endswith("/"):
        return False
    return bool(re.match(r"^[a-zA-Z0-9_\-\.\/]+$", branch_name))
