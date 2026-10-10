"""Patch explainability and compliance audit rationale generator."""

from typing import List, Optional
from agent_engine.state import Finding, RemediationState, VerificationResult


class RemediationExplainer:
    """Generates structured, human-readable explanations of security patches."""

    @staticmethod
    def format_rationale_markdown(state: RemediationState) -> str:
        """Format comprehensive remediation rationale into markdown."""
        finding = state.finding
        cwe_str = ", ".join(finding.cwe_ids) if finding.cwe_ids else "N/A"
        
        md_lines = [
            f"## Security Remediation Rationale: {finding.title}",
            "",
            f"- **Vulnerability ID**: `{finding.rule_id}`",
            f"- **Severity**: **{finding.severity.value}** (CVSS: {finding.cvss_score or 'N/A'})",
            f"- **CWE**: {cwe_str}",
            f"- **Affected Target**: `{finding.file_path}` (Lines {finding.start_line}-{finding.end_line})",
            "",
            "### Vulnerability Summary",
            finding.description or "Automated finding detected by security scanner.",
            "",
            "### Remediation Strategy",
            state.patch_explanation or "The patch neutralizes the vulnerability while preserving functional logic.",
            "",
            "### Verification & Quality Assurance Evidence",
        ]

        if state.verification_results:
            last_res = state.verification_results[-1]
            status_symbol = "[PASS]" if last_res.passed else "[FAIL]"
            md_lines.extend([
                f"- **Overall Verdict**: {status_symbol}",
                f"- **Regression Unit Tests**: {'PASSED' if last_res.functional_tests_passed else 'FAILED'}",
                f"- **Security Re-scan**: {'CLEAN' if last_res.security_tests_passed else 'DIRTY'}",
                f"- **Syntax Integrity**: {'VALID' if last_res.syntax_valid else 'INVALID'}",
                f"- **Verification Duration**: `{last_res.duration_seconds:.2f}s`"
            ])
        else:
            md_lines.append("- *No verification execution records found.*")

        md_lines.extend([
            "",
            "### Safe Rollback Instructions",
            "In case of unexpected regressions, revert this commit using:",
            f"```bash\ngit revert {state.commit_sha or 'HEAD'}\n```",
            ""
        ])

        return "\n".join(md_lines)
