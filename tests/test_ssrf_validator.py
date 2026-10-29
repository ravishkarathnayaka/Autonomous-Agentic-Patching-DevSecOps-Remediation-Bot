from agent_engine.tools.ssrf_validator import SSRFValidator


def test_ssrf_validator_prohibited_scheme():
    res = SSRFValidator.validate_url("file:///etc/passwd")
    assert res["safe"] is False
    assert "scheme" in res["reason"]


def test_ssrf_validator_loopback():
    res = SSRFValidator.validate_url("http://127.0.0.1:8080/admin")
    assert res["safe"] is False
    assert "loopback" in res["reason"]


def test_ssrf_validator_private_ip():
    res = SSRFValidator.validate_url("http://192.168.1.1/setup")
    assert res["safe"] is False
    assert "private network" in res["reason"]


def test_ssrf_validator_metadata_endpoint():
    res = SSRFValidator.validate_url("http://169.254.169.254/latest/meta-data/")
    assert res["safe"] is False
    assert "metadata" in res["reason"]
