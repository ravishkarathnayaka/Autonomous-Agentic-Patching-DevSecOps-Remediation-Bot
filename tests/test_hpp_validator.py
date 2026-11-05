from agent_engine.tools.hpp_validator import HppValidator


def test_hpp_validator_detects_duplicate_keys():
    url = "https://bank.example.com/api/transfer?recipient=alice&amount=100&recipient=attacker"
    is_safe, reason, params = HppValidator.validate_query_string(url)

    assert not is_safe
    assert "HTTP Parameter Pollution detected" in reason
    assert "'recipient'" in reason
    assert len(params["recipient"]) == 2


def test_hpp_validator_allows_clean_query():
    qs = "recipient=alice&amount=100"
    is_safe, reason, params = HppValidator.validate_query_string(qs)

    assert is_safe
    assert "No unexpected duplicate" in reason
    assert len(params["recipient"]) == 1


def test_hpp_validator_allows_explicit_multi_keys():
    qs = "tags=security&tags=devops&status=active"
    is_safe, reason, params = HppValidator.validate_query_string(qs, allowed_multi_keys=["tags"])

    assert is_safe
    assert len(params["tags"]) == 2
