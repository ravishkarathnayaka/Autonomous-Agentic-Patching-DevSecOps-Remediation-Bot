"""Triage Agent: Ingests vulnerability findings, resolves source context, and enriches AST metadata."""

import logging
from pathlib import Path
from typing import Optional

from agent_engine.state import Finding, RemediationState, RemediationStatus
from agent_engine.tools.ast_parser import extract_ast_context

logger = logging.getLogger(__name__)


class TriageAgent:
    """Agent responsible for inspecting findings and enriching code context."""

    def __init__(self, name: str = "TriageAgent"):
        self.name = name

    def execute(self, state: RemediationState) -> RemediationState:
        """Analyze the target finding, locate the source file, and attach AST context."""
        finding: Finding = state.finding
        repo_root = Path(state.target_repo_path).resolve()

        state.log_event(self.name, "start_triage", {"finding_id": finding.id, "rule_id": finding.rule_id})

        # Locate file on disk
        target_file_path = self._resolve_file_path(repo_root, finding.file_path)
        if not target_file_path or not target_file_path.is_file():
            state.status = RemediationStatus.FAILED
            state.last_error_trace = f"Target file not found in repo: {finding.file_path}"
            state.log_event(self.name, "file_not_found", {"path": finding.file_path})
            return state

        # Read source code
        try:
            with open(target_file_path, "r", encoding="utf-8", errors="replace") as f:
                source_code = f.read()
        except Exception as e:
            state.status = RemediationStatus.FAILED
            state.last_error_trace = f"Failed to read file {target_file_path}: {e}"
            state.log_event(self.name, "read_error", {"error": str(e)})
            return state

        # Extract snippet if not provided
        lines = source_code.splitlines()
        start_idx = max(0, finding.start_line - 1)
        end_idx = min(len(lines), max(finding.end_line, finding.start_line))
        if not finding.vulnerable_code and lines:
            finding.vulnerable_code = "\n".join(lines[start_idx:end_idx])

        # If Python file, extract AST context
        if target_file_path.suffix.lower() == ".py":
            ast_ctx = extract_ast_context(source_code, finding.start_line)
            finding.ast_context = ast_ctx.context_summary + "\n" + ast_ctx.surrounding_snippet
        else:
            # For non-python files (e.g. requirements.txt or config files)
            finding.ast_context = f"Non-Python resource: {target_file_path.name}"

        state.status = RemediationStatus.TRIAGED
        state.log_event(self.name, "triage_complete", {
            "resolved_path": str(target_file_path),
            "start_line": finding.start_line,
            "end_line": finding.end_line,
            "cwe_ids": finding.cwe_ids
        })

        return state

    def _resolve_file_path(self, repo_root: Path, file_path_str: str) -> Optional[Path]:
        """Find the file within repository root handling relative or prefixed paths."""
        direct = repo_root / file_path_str
        if direct.is_file():
            return direct

        # Try stripping leading repo folder name if present
        parts = Path(file_path_str).parts
        if len(parts) > 1 and parts[0] == repo_root.name:
            candidate = repo_root.joinpath(*parts[1:])
            if candidate.is_file():
                return candidate

        # Search by basename
        file_name = Path(file_path_str).name
        for match in repo_root.rglob(file_name):
            if match.is_file():
                return match

        return None
