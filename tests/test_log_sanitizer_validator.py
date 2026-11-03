import pytest
from agent_engine.tools.log_sanitizer_validator import LogSanitizerValidator


def test_log_sanitizer_safe_message():
    is_safe, reason = LogSanitizerValidator.is_safe_log_message("User alice authenticated successfully")
    assert is_safe is True
    assert "Safe" in reason


def test_log_sanitizer_crlf_detection():
    is_safe, reason = LogSanitizerValidator.is_safe_log_message("admin\nAUDIT: user='hacker' logged in")
    assert is_safe is False
    assert "CRLF" in reason


def test_log_sanitizer_ansi_detection():
    is_safe, reason = LogSanitizerValidator.is_safe_log_message("status: \x1b[31mCRITICAL\x1b[0m")
    assert is_safe is False
    assert "ANSI" in reason


def test_log_sanitizer_clean_method():
    raw = "malicious_user\r\n[CRITICAL] Admin password reset\x1b[31m"
    cleaned = LogSanitizerValidator.sanitize(raw)
    assert "\r" not in cleaned
    assert "\n" not in cleaned
    assert "\x1b" not in cleaned
    assert "malicious_user" in cleaned
