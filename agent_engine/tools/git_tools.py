"""Git automation tools for branching, patch staging, worktree isolation, and committing."""

import os
from pathlib import Path
import re
import subprocess
from typing import List, Optional, Tuple


def _run_git(args: List[str], cwd: str) -> Tuple[int, str, str]:
    """Execute a git command in the specified directory."""
    try:
        proc = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "git executable not found in PATH"
    except Exception as e:
        return 1, "", str(e)


def is_git_repo(repo_path: str) -> bool:
    """Check if the given directory is the root of a valid git repository."""
    git_dir = Path(repo_path) / ".git"
    if git_dir.exists():
        return True
    code, out, _ = _run_git(["rev-parse", "--show-toplevel"], cwd=repo_path)
    if code == 0 and out:
        return Path(out).resolve() == Path(repo_path).resolve()
    return False


def create_security_branch(repo_path: str, branch_name: str) -> Tuple[bool, str]:
    """Create and checkout a new security remediation branch."""
    if not is_git_repo(repo_path):
        return False, "Not a git repository"

    # Checkout -B to create or reset branch to current HEAD
    code, out, err = _run_git(["checkout", "-B", branch_name], cwd=repo_path)
    if code != 0:
        return False, f"Failed to create branch {branch_name}: {err or out}"
    return True, f"Switched to branch {branch_name}"


def get_current_branch(repo_path: str) -> Optional[str]:
    """Get the currently checked out branch name."""
    code, out, _ = _run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path)
    return out if code == 0 else None


def apply_patch_file(repo_path: str, patch_content: str) -> Tuple[bool, str]:
    """Apply a unified diff patch to the repository with git apply or fallback applier."""
    if not patch_content.strip():
        return False, "Empty patch content"

    # Normalize CRLF/LF line endings in patch
    normalized_patch = patch_content.replace("\r\n", "\n")
    if not normalized_patch.endswith("\n"):
        normalized_patch += "\n"

    # First attempt: git apply with multiple strip prefixes (-p1, -p2, -p0)
    temp_patch_path = os.path.join(repo_path, ".remediation_temp.patch")
    try:
        with open(temp_patch_path, "w", encoding="utf-8", newline="\n") as f:
            f.write(normalized_patch)

        for p_flag in ["-p1", "-p2", "-p0"]:
            code, out, err = _run_git([
                "apply",
                p_flag,
                "--ignore-whitespace",
                "--ignore-space-change",
                "--whitespace=nowarn",
                temp_patch_path
            ], cwd=repo_path)
            if code == 0:
                return True, f"Patch applied cleanly via git apply ({p_flag})"

        # Attempt 2: 3-way merge if supported
        for p_flag in ["-p1", "-p2", "-p0"]:
            code_3way, out_3way, err_3way = _run_git([
                "apply",
                "-3",
                p_flag,
                "--ignore-whitespace",
                temp_patch_path
            ], cwd=repo_path)
            if code_3way == 0:
                return True, f"Patch applied cleanly via git apply 3-way ({p_flag})"

        # Fallback: Python manual block replacer for simple hunk modifications
        fallback_ok, fallback_msg = _python_patch_fallback(repo_path, normalized_patch)
        if fallback_ok:
            return True, f"Patch applied via fallback parser: {fallback_msg}"

        return False, f"git apply failed: {err or out}"
    finally:
        if os.path.exists(temp_patch_path):
            try:
                os.remove(temp_patch_path)
            except OSError:
                pass


def _python_patch_fallback(repo_path: str, diff_text: str) -> Tuple[bool, str]:
    """Fallback unified diff applier for single/multi-file patches."""
    try:
        file_diffs = re.split(r"(?=diff --git |--- a/)", diff_text)
        applied_files = []

        for fdiff in file_diffs:
            if not fdiff.strip():
                continue
            # Extract target file path
            match = re.search(r"--- a/(.*?)\n\+\+\+ b/(.*?)\n", fdiff)
            if not match:
                match = re.search(r"\+\+\+ b/(.*?)\n", fdiff)
                if not match:
                    continue
                target_rel_path = match.group(1).strip()
            else:
                target_rel_path = match.group(2).strip()

            target_full_path = os.path.join(repo_path, target_rel_path)
            if not os.path.exists(target_full_path):
                # Check if file path is direct or relative
                for candidate in Path(repo_path).rglob(os.path.basename(target_rel_path)):
                    target_full_path = str(candidate)
                    break

            if not os.path.exists(target_full_path):
                continue

            with open(target_full_path, "r", encoding="utf-8", errors="replace") as f:
                original_text = f.read().replace("\r\n", "\n")

            # Process hunks
            hunks = re.split(r"(?=@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@)", fdiff)

            file_modified = False
            for hunk in hunks[1:]:
                removed = []
                added = []
                for line in hunk.split("\n")[1:]:
                    if line.startswith("-") and not line.startswith("---"):
                        removed.append(line[1:].rstrip("\r\n"))
                    elif line.startswith("+") and not line.startswith("+++"):
                        added.append(line[1:].rstrip("\r\n"))

                if removed:
                    old_block = "\n".join(removed)
                    new_block = "\n".join(added)
                    if old_block in original_text:
                        original_text = original_text.replace(old_block, new_block, 1)
                        file_modified = True

            if file_modified:
                with open(target_full_path, "w", encoding="utf-8", newline="\n") as f:
                    f.write(original_text)
                applied_files.append(target_rel_path)

        if applied_files:
            return True, f"Modified {', '.join(applied_files)}"
        return False, "Could not match patch hunks in target files"
        return False, "Could not match patch hunks"
    except Exception as e:
        return False, f"Fallback patch error: {str(e)}"


def get_git_diff(repo_path: str) -> str:
    """Get the current uncommitted git diff in the repo."""
    code, out, _ = _run_git(["diff", "HEAD"], cwd=repo_path)
    if code != 0 or not out:
        code, out, _ = _run_git(["diff"], cwd=repo_path)
    return out if code == 0 else ""


def commit_all(repo_path: str, message: str) -> Tuple[bool, Optional[str]]:
    """Stage all changes and create a commit."""
    _run_git(["add", "-A"], cwd=repo_path)
    code, out, err = _run_git(["commit", "-m", message], cwd=repo_path)
    if code != 0:
        return False, err or out

    # Get commit SHA
    c_code, c_sha, _ = _run_git(["rev-parse", "HEAD"], cwd=repo_path)
    return True, c_sha if c_code == 0 else None


def reset_working_tree(repo_path: str) -> bool:
    """Hard reset working directory changes on tracked files."""
    code1, _, _ = _run_git(["reset", "--hard", "HEAD"], cwd=repo_path)
    code2, _, _ = _run_git(["checkout", "--", "."], cwd=repo_path)
    return (code1 == 0 or code2 == 0)
