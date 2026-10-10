from pathlib import Path
import pytest
from agent_engine.tools.hook_installer import GitHookInstaller


def test_hook_installer_lifecycle(tmp_path: Path):
    # Setup mock git repo
    git_dir = tmp_path / ".git"
    git_dir.mkdir()

    assert GitHookInstaller.is_hook_installed(tmp_path) is False

    # Install
    success, msg = GitHookInstaller.install_pre_commit_hook(tmp_path)
    assert success is True
    assert "Hook installed" in msg
    assert GitHookInstaller.is_hook_installed(tmp_path) is True

    # Check contents
    hook_file = git_dir / "hooks" / "pre-commit"
    assert hook_file.exists()
    content = hook_file.read_text(encoding="utf-8")
    assert "gitleaks" in content
    assert "bandit" in content

    # Uninstall
    uninstalled = GitHookInstaller.uninstall_hook(tmp_path)
    assert uninstalled is True
    assert GitHookInstaller.is_hook_installed(tmp_path) is False
