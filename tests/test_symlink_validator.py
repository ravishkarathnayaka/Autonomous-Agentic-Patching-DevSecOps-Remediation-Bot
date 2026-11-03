import os
import pytest
from agent_engine.tools.symlink_validator import SymlinkSecurityValidator


def test_symlink_validator_safe_relative():
    base = os.path.abspath("safe_dir")
    is_safe, reason = SymlinkSecurityValidator.is_safe_path(base, "docs/report.txt")
    assert is_safe is True
    assert "Safe" in reason


def test_symlink_validator_traversal_blocked():
    base = os.path.abspath("safe_dir")
    is_safe, reason = SymlinkSecurityValidator.is_safe_path(base, "../../etc/shadow")
    assert is_safe is False
    assert "escapes base directory" in reason


def test_symlink_validator_absolute_blocked():
    base = os.path.abspath("safe_dir")
    is_safe, reason = SymlinkSecurityValidator.is_safe_path(base, "/var/log/syslog")
    assert is_safe is False
    assert "Absolute path not permitted" in reason
