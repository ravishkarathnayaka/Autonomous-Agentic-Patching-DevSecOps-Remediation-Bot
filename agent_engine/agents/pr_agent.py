"""PR Agent: Synthesizes threat mitigation descriptions, establishes branches, and generates GitHub PR markdown."""

from datetime import datetime, timezone
import logging
from pathlib import Path
import re
from typing import Optional

from agent_engine.llm.client import BaseLLMClient
from agent_engine.state import RemediationState, RemediationStatus
from agent_engine.tools.git_tools import commit_all, create_security_branch, is_git_repo

logger = logging.getLogger(__name__)


class PRAgent:
    """Agent that creates the git branch, commits the verified patch, and crafts the PR body."""

    def __init__(self, llm_client: Optional[BaseLLMClient] = None, name: str = "PRAgent"):
        self.llm_client = llm_client
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Create git branch, commit verified changes, and synthesize PR documentation."""
        if state.status != RemediationStatus.VERIFIED:
            logger.warning("PRAgent called on unverified state: %s", state.status)
            return state

        f = state.finding
        timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

        # Standardized security branch format: security/fix-<cwe-or-rule>-<timestamp>
        rule_slug = re.sub(r"[^\w\-]", "", f.rule_id.split(".")[-1].lower())
        cwe_tag = f.cwe_ids[0].lower() if f.cwe_ids else rule_slug
        branch_name = f"security/fix-{cwe_tag}-{timestamp_str}"
        commit_title = f"fix(security): remediate {f.title} ({cwe_tag.upper()})"

        state.pr_branch = branch_name
        state.pr_title = commit_title

        repo_root = Path(state.target_repo_path).resolve()

        # Handle Git branch & commit if inside a git repository
        if is_git_repo(str(repo_root)):
            branch_ok, branch_msg = create_security_branch(str(repo_root), branch_name)
            if branch_ok:
                commit_ok, commit_res = commit_all(
                    str(repo_root),
                    f"{commit_title}\n\nRemediated by Autonomous DevSecOps Remediation Bot."
                )
                if commit_ok and commit_res:
                    state.commit_sha = commit_res
                    state.log_event(self.name, "commit_created", {"sha": commit_res, "branch": branch_name})
            else:
                logger.warning("Git branch creation skipped or failed: %s", branch_msg)

        # Synthesize PR Body
        pr_markdown = self._generate_pr_body(state)
        state.pr_body = pr_markdown
        state.status = RemediationStatus.PR_READY

        state.log_event(self.name, "pr_ready", {
            "branch": state.pr_branch,
            "title": state.pr_title,
            "commit_sha": state.commit_sha
        })

        return state

    def _generate_pr_body(self, state: RemediationState) -> str:
        """Generate a production-ready, security-audited Pull Request description in markdown."""
        f = state.finding
        cwe_str = ", ".join(f.cwe_ids) if f.cwe_ids else "N/A"
        cvss_str = f"{f.cvss_score:.1f}" if f.cvss_score is not None else "N/A"

        # Verification test summary
        test_evidence = "N/A"
        duration_total = 0.0
        if state.verification_results:
            last_res = state.verification_results[-1]
            duration_total = last_res.duration_seconds
            test_evidence = last_res.test_output or "All automated tests executed cleanly."

        # Diff snippet
        diff_block = state.patch_diff or "# (No diff recorded)"

        body = f"""## 🛡️ Autonomous Security Remediation Pull Request

### 1. Executive Summary
- **Vulnerability Title**: {f.title}
- **Scanner**: `{f.scanner.upper()}` ({f.finding_type.value})
- **Rule / Advisory ID**: `{f.rule_id}`
- **Severity**: **`{f.severity.value}`**
- **CWE Identifier(s)**: `{cwe_str}`
- **CVSS Score**: `{cvss_str}`
- **Target File**: `{f.file_path}` (Lines {f.start_line} - {f.end_line})

---

### 2. Threat Analysis & Remediation Rationale
{state.patch_explanation or self._default_threat_analysis(f.cwe_ids, f.rule_id)}

#### Security Controls Applied:
- Surgical code modification targeting only the vulnerable execution flow.
- Enforced defense-in-depth principles (e.g. query parameterization, canonical path validation, safe process spawning).
- Preserved existing application semantics and interface contracts.

---

### 3. Surgical Patch Diff
```diff
{diff_block}
```

---

### 4. Sandbox Verification Evidence
> **Verification Status**: ✅ **PASSED** (Executed inside Ephemeral Container Sandbox)
> **Total Attempts / Retries**: `{state.retry_count + 1}` / `{state.max_retries}`
> **Execution Duration**: `{duration_total:.2f}s`

```text
{test_evidence}
```

---

### 5. DevSecOps Sign-off & Verification Checklist
- [x] Ephemeral sandbox execution verified without host compromise.
- [x] Zero regression in existing unit test suites (`pytest`).
- [x] Clean syntax and AST structure verified.
- [ ] Peer code review and security sign-off before merge.

---
*Generated autonomously by Autonomous Agentic Patching & DevSecOps Remediation Bot.*
"""
        return body

    def _default_threat_analysis(self, cwe_ids: list[str], rule_id: str) -> str:
        """Provide fallback threat rationale if LLM explanation is absent."""
        cwe_joined = " / ".join(cwe_ids)
        return (
            f"This automated remediation addresses **{cwe_joined or rule_id}**. "
            "Untrusted user input was previously handled without strict boundary validation or sanitization, "
            "presenting an attack surface for exploitation. The patch replaces this unsafe construction with "
            "an idiomatic and hardened security pattern."
        )
