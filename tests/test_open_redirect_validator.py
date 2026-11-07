from agent_engine.tools.open_redirect_validator import OpenRedirectValidator


def test_open_redirect_blocks_protocol_relative():
    is_safe, reason = OpenRedirectValidator.validate_target("//attacker.com/login")
    assert not is_safe
    assert "Protocol-relative" in reason


def test_open_redirect_blocks_backslash_trick():
    is_safe, reason = OpenRedirectValidator.validate_target("https://trusted.corp.com\\@attacker.com")
    assert not is_safe
    assert "Backslash" in reason


def test_open_redirect_blocks_javascript_scheme():
    is_safe, reason = OpenRedirectValidator.validate_target("javascript:alert(1)")
    assert not is_safe
    assert "Prohibited URI scheme" in reason


def test_open_redirect_allows_clean_relative():
    is_safe, reason = OpenRedirectValidator.validate_target("/dashboard/home")
    assert is_safe
    assert "Safe internal relative" in reason


def test_open_redirect_whitelist_verification():
    assert OpenRedirectValidator.is_safe_redirect(
        "https://trusted.corp.com/oauth/callback",
        allowed_hosts=["trusted.corp.com"]
    )
    assert not OpenRedirectValidator.is_safe_redirect(
        "https://evil.corp.com/steal",
        allowed_hosts=["trusted.corp.com"]
    )
