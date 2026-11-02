import os
import pytest
from agent_engine.tools.zip_slip_validator import ZipSlipValidator


def test_zip_slip_safe_path():
    target = os.path.abspath("safe_extract_folder")
    is_safe, reason = ZipSlipValidator.is_safe_member_path("sub/folder/file.txt", target)
    assert is_safe is True
    assert "Safe" in reason


def test_zip_slip_traversal_detection():
    target = os.path.abspath("safe_extract_folder")
    is_safe, reason = ZipSlipValidator.is_safe_member_path("../../etc/passwd", target)
    assert is_safe is False
    assert "Zip Slip" in reason or "escapes" in reason


def test_zip_slip_absolute_path():
    target = os.path.abspath("safe_extract_folder")
    is_safe, reason = ZipSlipValidator.is_safe_member_path("/etc/shadow", target)
    assert is_safe is False
    assert "absolute" in reason


def test_find_unsafe_members():
    target = os.path.abspath("safe_extract_folder")
    members = ["valid.txt", "../escape.py", "nested/good.json", "nested/../../bad.sh"]
    unsafe = ZipSlipValidator.find_unsafe_members(members, target)
    assert "../escape.py" in unsafe
    assert "nested/../../bad.sh" in unsafe
    assert "valid.txt" not in unsafe
