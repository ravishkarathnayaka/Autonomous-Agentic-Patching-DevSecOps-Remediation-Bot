import pytest
from agent_engine.tools.ldap_filter_validator import LdapFilterValidator


def test_ldap_safe_value():
    is_safe, reason = LdapFilterValidator.is_safe_filter_value("alice_smith")
    assert is_safe is True
    assert "Safe" in reason


def test_ldap_unsafe_breakout():
    is_safe, reason = LdapFilterValidator.is_safe_filter_value("admin)(|(password=*")
    assert is_safe is False
    assert "breakout" in reason or "parentheses" in reason


def test_ldap_escape_filter():
    raw = "admin*(user)\\test"
    escaped = LdapFilterValidator.escape_filter_value(raw)
    assert "\\2a" in escaped
    assert "\\28" in escaped
    assert "\\29" in escaped
    assert "\\5c" in escaped
