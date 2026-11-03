import base64
import json
import time
from click.testing import CliRunner
from cli.audit_jwt import audit_jwt


def _generate_test_token(header: dict, payload: dict, sig: str = "sig123") -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.{sig}"


def test_cli_audit_jwt_clean():
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "service-account", "exp": int(time.time()) + 3600}
    token = _generate_test_token(header, payload)

    runner = CliRunner()
    result = runner.invoke(audit_jwt, ["--token", token])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["is_compliant"] is True
    assert parsed["issue_count"] == 0


def test_cli_audit_jwt_vulnerable():
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "root"}
    token = _generate_test_token(header, payload, sig="")

    runner = CliRunner()
    result = runner.invoke(audit_jwt, ["--token", token])
    assert result.exit_code == 1
    parsed = json.loads(result.output)
    assert parsed["is_compliant"] is False
    assert any("none" in i["issue"] for i in parsed["issues"])
