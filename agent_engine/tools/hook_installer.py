"""Git pre-commit hook installer and security policy enforcer."""

import os
from pathlib import Path
import stat
from typing import Optional, Tuple


PRE_COMMIT_SCRIPT_TEMPLATE = """#!/usr/bin/env bash
# Autonomous DevSecOps Remediation Bot - Pre-Commit Security Hook
set -e

echo "[DevSecOps Guard] Running pre-commit security verification..."

# 1. Secret Scanning
if command -v gitleaks &> /dev/null; then
    gitleaks protect --staged --verbose || {
        echo "[!] Pre-commit blocked: Secret detected in staged changes."
        exit 1
    }
fi

# 2. Python Security Linting
if command -v bandit &> /dev/null; then
    bandit -q -r target_repo/ || {
        echo "[!] Pre-commit blocked: High-severity security flaw detected."
        exit 1
    }
fi

echo "[DevSecOps Guard] Security checks passed."
exit 0
"""


class GitHookInstaller:
    """Manages installation and status of client-side git security hooks."""

    @staticmethod
    def install_pre_commit_hook(repo_root: Path) -> Tuple[bool, str]:
        """Install pre-commit security hook into .git/hooks directory."""
        git_dir = repo_root / ".git"
        if not git_dir.exists():
            return False, f"Directory {repo_root} is not a git repository."

        hooks_dir = git_dir / "hooks"
        hooks_dir.mkdir(parents=True, exist_ok=True)
        hook_path = hooks_dir / "pre-commit"

        try:
            hook_path.write_text(PRE_COMMIT_SCRIPT_TEMPLATE, encoding="utf-8")
            # Make executable
            current_perms = hook_path.stat().st_mode
            hook_path.chmod(current_perms | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            return True, f"Hook installed at {hook_path}"
        except Exception as e:
            return False, f"Failed to install hook: {e}"

    @staticmethod
    def is_hook_installed(repo_root: Path) -> bool:
        """Check if pre-commit security hook is currently active."""
        hook_path = repo_root / ".git" / "hooks" / "pre-commit"
        if not hook_path.is_file():
            return False
        content = hook_path.read_text(encoding="utf-8", errors="ignore")
        return "Autonomous DevSecOps Remediation Bot" in content

    @staticmethod
    def uninstall_hook(repo_root: Path) -> bool:
        """Remove installed pre-commit hook."""
        hook_path = repo_root / ".git" / "hooks" / "pre-commit"
        if hook_path.is_file():
            hook_path.unlink()
            return True
        return False
