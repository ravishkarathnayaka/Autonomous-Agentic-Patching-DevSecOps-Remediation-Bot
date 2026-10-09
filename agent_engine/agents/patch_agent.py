"""Patch Agent: Orchestrates LLM prompting to synthesize minimal, surgical security patches."""

import logging
import re
from typing import Optional

from agent_engine.llm.client import BaseLLMClient
from agent_engine.state import FindingType, RemediationState, RemediationStatus

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an elite Application Security and DevSecOps Engineer.
Your task is to generate a minimal, surgical, idiomatic unified git diff to remediate the reported security vulnerability.

Rules:
1. Output MUST include a valid unified git diff inside a ```diff ... ``` block.
2. The diff must use standard unified headers (e.g. --- a/<filepath> and +++ b/<filepath>).
3. Do not modify unrelated code, preserve indentation and code style.
4. For SQL Injection (CWE-89): Use parameterized queries / placeholders instead of string formatting or concatenation.
5. For Path Traversal (CWE-22): Canonicalize paths using os.path.abspath and ensure the
   resolved path stays within the intended base directory.
6. For Command Injection (CWE-78): Avoid shell=True. Use a list of arguments and validate input.
7. For SCA Vulnerabilities: Update the pinned version in requirements.txt to the recommended fixed version.
8. If error feedback from a previous failed verification is provided, analyze the error and fix it completely.
9. Provide a brief explanation of the remediation rationale after the diff."""


class PatchAgent:
    """Agent responsible for crafting prompts and generating security diffs via LLM."""

    def __init__(self, llm_client: BaseLLMClient, name: str = "PatchAgent"):
        self.llm_client = llm_client
        self.name = name

    @staticmethod
    def compute_temperature(retry_count: int, base_temp: float = 0.0, step: float = 0.2, max_temp: float = 0.7) -> float:
        """Anneal sampling temperature across self-healing retry attempts for exploration."""
        return min(max_temp, round(base_temp + (retry_count * step), 2))

    def execute(self, state: RemediationState) -> RemediationState:
        """Synthesize a patch based on finding details, AST context, and verification feedback."""
        temperature = self.compute_temperature(state.retry_count)
        state.log_event(self.name, "start_patching", {
            "retry_count": state.retry_count,
            "temperature": temperature,
            "has_error_feedback": bool(state.last_error_trace)
        })

        prompt = self._build_prompt(state)

        try:
            response = self.llm_client.generate(prompt=prompt, system_prompt=SYSTEM_PROMPT, temperature=temperature)
        except Exception as e:
            logger.error("LLM patch generation call failed: %s", e)
            state.status = RemediationStatus.FAILED
            state.last_error_trace = f"LLM generation failed: {e}"
            state.log_event(self.name, "llm_error", {"error": str(e)})
            return state

        diff_text = self._extract_diff(response)
        if not diff_text:
            state.status = RemediationStatus.FAILED
            state.last_error_trace = "LLM response did not contain a valid unified diff"
            state.log_event(self.name, "missing_diff_error", {"raw_response": response[:200]})
            return state

        state.patch_diff = diff_text
        state.patch_explanation = self._extract_explanation(response)
        state.status = RemediationStatus.PATCH_GENERATED

        state.log_event(self.name, "patch_generated", {
            "diff_length": len(diff_text),
            "explanation": state.patch_explanation[:100] if state.patch_explanation else ""
        })

        return state

    def _build_prompt(self, state: RemediationState) -> str:
        """Construct the prompt instructing the LLM on the vulnerability and code context."""
        f = state.finding
        cwe_str = ", ".join(f.cwe_ids) if f.cwe_ids else "N/A"
        cvss_str = str(f.cvss_score) if f.cvss_score is not None else "N/A"

        prompt_lines = [
            f"# Security Vulnerability Remediation Request (Attempt #{state.retry_count + 1})",
            "",
            f"- Scanner: {f.scanner.upper()} ({f.finding_type.value})",
            f"- Rule / Vulnerability ID: {f.rule_id}",
            f"- Title: {f.title}",
            f"- Severity: {f.severity.value}",
            f"- CWE: {cwe_str}",
            f"- CVSS Base Score: {cvss_str}",
            f"- Target File: {f.file_path}",
            f"- Flagged Lines: {f.start_line} - {f.end_line}",
            "",
            "## Vulnerability Description",
            f.description,
            "",
            "## Flagged Code Snippet",
            "```",
            f.vulnerable_code or "# (no snippet available)",
            "```",
            "",
            "## Surrounding Code Context & AST Structure",
            "```",
            f.ast_context or "# (no AST context available)",
            "```",
        ]

        if f.finding_type == FindingType.SCA:
            prompt_lines.extend([
                "",
                "## SCA Dependency Information",
                f"- Package: {f.package_name}",
                f"- Installed Version: {f.installed_version}",
                f"- Fixed Version: {f.fixed_version or 'Latest secure patch'}",
            ])

        # If this is a retry attempt, inject the failure diagnostics
        if state.last_error_trace and state.retry_count > 0:
            prompt_lines.extend([
                "",
                "## ⚠️ Previous Verification Attempt Failed!",
                "The previous patch attempt failed verification. Analyze the following error trace and adjust your patch:",
                "```text",
                state.last_error_trace,
                "```",
            ])

        prompt_lines.extend([
            "",
            "Generate the minimal unified diff to fix this vulnerability. Enclose the diff in ```diff ... ```."
        ])

        return "\n".join(prompt_lines)

    def _extract_diff(self, response_text: str) -> Optional[str]:
        """Extract unified diff from LLM markdown code blocks or raw diff text."""
        # 1. Look for ```diff ... ``` or ```patch ... ```
        block_match = re.search(r"```(?:diff|patch)?\s*\n(.*?)\n```", response_text, re.DOTALL)
        if block_match:
            candidate = block_match.group(1).strip()
            if "---" in candidate or "+++" in candidate:
                return candidate

        # 2. Look for raw unified diff headers
        diff_match = re.search(r"(--- a/.*?)(?:\n\n|\Z)", response_text, re.DOTALL)
        if diff_match:
            return diff_match.group(1).strip()

        return None

    def _extract_explanation(self, response_text: str) -> Optional[str]:
        """Extract explanation commentary outside of the diff block."""
        cleaned = re.sub(r"```(?:diff|patch)?\s*\n.*?\n```", "", response_text, flags=re.DOTALL)
        cleaned = cleaned.strip()
        return cleaned if cleaned else None
