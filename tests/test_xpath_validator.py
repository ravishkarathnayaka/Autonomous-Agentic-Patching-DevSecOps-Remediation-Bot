import pytest
from agent_engine.tools.xpath_validator import XPathValidator


def test_xpath_safe_literal():
    is_safe, reason = XPathValidator.is_safe_literal("JohnDoe")
    assert is_safe is True
    assert "Safe" in reason


def test_xpath_unsafe_boolean_injection():
    is_safe, reason = XPathValidator.is_safe_literal("' or '1'='1")
    assert is_safe is False
    assert "injection" in reason.lower()


def test_xpath_unsafe_mixed_quotes():
    is_safe, reason = XPathValidator.is_safe_literal("O'Reilly\"")
    assert is_safe is False
    assert "both single and double" in reason


def test_xpath_sanitize_literal():
    sanitized = XPathValidator.sanitize_literal("alice")
    assert sanitized == "'alice'"

    sanitized_quote = XPathValidator.sanitize_literal("O'Connor")
    assert sanitized_quote == '"O\'Connor"'
