import pickle
from agent_engine.tools.pickle_safety_inspector import PickleSafetyInspector


class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ("id",))


def test_pickle_inspector_detects_malicious_payload():
    malicious_bytes = pickle.dumps(Exploit())
    is_safe, violations = PickleSafetyInspector.inspect_bytes(malicious_bytes)

    assert not is_safe
    assert len(violations) > 0
    assert any("os" in v or "system" in v for v in violations)


def test_pickle_inspector_allows_primitive_dict():
    clean_bytes = pickle.dumps({"name": "alice", "count": 42})
    is_safe, violations = PickleSafetyInspector.inspect_bytes(clean_bytes)

    assert is_safe
    assert len(violations) == 0


def test_pickle_inspector_rejects_empty():
    is_safe, violations = PickleSafetyInspector.inspect_bytes(b"")
    assert not is_safe
    assert "empty" in violations[0]
