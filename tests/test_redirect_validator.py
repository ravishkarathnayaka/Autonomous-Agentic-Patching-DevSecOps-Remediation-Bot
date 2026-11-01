from agent_engine.tools.redirect_validator import RedirectValidator


def test_redirect_validator_relative_path():
    validator = RedirectValidator()
    is_safe, _ = validator.validate_redirect_url("/dashboard/settings")
    assert is_safe is True


def test_redirect_validator_protocol_relative():
    validator = RedirectValidator()
    is_safe, reason = validator.validate_redirect_url("//evil.com/login")
    assert is_safe is False
    assert "Protocol-relative" in reason


def test_redirect_validator_javascript_scheme():
    validator = RedirectValidator()
    is_safe, reason = validator.validate_redirect_url("javascript:alert(1)")
    assert is_safe is False
    assert "Dangerous scheme" in reason


def test_redirect_validator_allowed_domain():
    validator = RedirectValidator(allowed_domains=["internal.corp", "enterprise.com"])
    is_safe, _ = validator.validate_redirect_url("https://app.enterprise.com/oauth/callback")
    assert is_safe is True

    is_safe, reason = validator.validate_redirect_url("https://attacker.com/steal")
    assert is_safe is False
    assert "not in approved allowlist" in reason
