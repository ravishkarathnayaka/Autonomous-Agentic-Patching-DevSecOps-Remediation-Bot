from agent_engine.tools.commit_signature_validator import CommitSignatureValidator


def test_verify_commit_head():
    result = CommitSignatureValidator.verify_commit("HEAD")
    assert "signed" in result
    assert "status" in result
    assert result["status"] in {"GOOD", "UNSIGNED", "UNTRUSTED_KEY", "UNKNOWN", "CANNOT_CHECK"}


def test_verify_invalid_ref():
    result = CommitSignatureValidator.verify_commit("nonexistent_commit_hash_123456789")
    assert result["signed"] is False
    assert result["status"] == "ERROR"
