from agent_engine.tools.pdf_uri_validator import PdfUriAllowlistValidator


def test_pdf_uri_validator_blocks_file_scheme():
    validator = PdfUriAllowlistValidator()
    is_safe, reason = validator.validate_url("file:///etc/passwd")
    assert not is_safe
    assert "Prohibited URI scheme" in reason


def test_pdf_uri_validator_blocks_metadata_ip():
    validator = PdfUriAllowlistValidator()
    is_safe, reason = validator.validate_url("http://169.254.169.254/latest/meta-data/")
    assert not is_safe
    assert "Prohibited target host" in reason or "internal/private" in reason


def test_pdf_uri_validator_blocks_private_ip():
    validator = PdfUriAllowlistValidator()
    is_safe, reason = validator.validate_url("http://192.168.1.50/internal-report")
    assert not is_safe
    assert "internal/private network" in reason


def test_pdf_uri_validator_allows_legitimate_https():
    validator = PdfUriAllowlistValidator()
    is_safe, reason = validator.validate_url("https://example.com/invoice/template")
    assert is_safe
    assert "URL is safe" in reason


def test_pdf_uri_validator_domain_allowlist():
    validator = PdfUriAllowlistValidator(allowed_domains=["trusted.example.com"])
    assert validator.is_safe_url("https://trusted.example.com/report")
    assert not validator.is_safe_url("https://untrusted.com/report")
