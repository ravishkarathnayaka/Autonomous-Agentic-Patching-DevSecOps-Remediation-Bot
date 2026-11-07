import base64
import pickle
from click.testing import CliRunner
from cli.audit_pickle import audit_pickle


class DangerousPayload:
    def __reduce__(self):
        import os
        return (os.system, ("id",))


def test_cli_audit_pickle_base64_pass():
    clean = base64.b64encode(pickle.dumps({"id": 100, "active": True})).decode("utf-8")
    runner = CliRunner()
    result = runner.invoke(audit_pickle, ["--base64", clean])
    assert result.exit_code == 0
    assert "[PASS]" in result.output


def test_cli_audit_pickle_base64_fail():
    evil = base64.b64encode(pickle.dumps(DangerousPayload())).decode("utf-8")
    runner = CliRunner()
    result = runner.invoke(audit_pickle, ["--base64", evil])
    assert result.exit_code == 1
    assert "[FAIL]" in result.output
    assert "Disallowed executable import" in result.output or "Dangerous opcode" in result.output


def test_cli_audit_pickle_file(tmp_path):
    f = tmp_path / "data.pkl"
    f.write_bytes(pickle.dumps([1, 2, 3]))
    runner = CliRunner()
    result = runner.invoke(audit_pickle, [str(f)])
    assert result.exit_code == 0
    assert "[PASS]" in result.output
