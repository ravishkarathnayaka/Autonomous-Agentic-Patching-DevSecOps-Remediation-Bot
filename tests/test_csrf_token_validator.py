import pytest
from agent_engine.tools.csrf_token_validator import CsrfTokenValidator


def test_csrf_get_request_allowed():
    valid, reason = CsrfTokenValidator.validate_request_csrf("GET", {})
    assert valid is True
    assert "read-only" in reason


def test_csrf_bearer_token_allowed():
    headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDc"}
    valid, reason = CsrfTokenValidator.validate_request_csrf("POST", headers)
    assert valid is True
    assert "Bearer" in reason


def test_csrf_valid_header():
    headers = {"X-CSRF-Token": "abcdef1234567890abcdef"}
    valid, reason = CsrfTokenValidator.validate_request_csrf("POST", headers)
    assert valid is True
    assert "Valid Anti-CSRF token" in reason


def test_csrf_missing_token_rejected():
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    valid, reason = CsrfTokenValidator.validate_request_csrf("POST", headers)
    assert valid is False
    assert "missing required Anti-CSRF" in reason
