from agent_engine.tools.provenance_verifier import ProvenanceVerifier


def test_provenance_verifier_chain_integrity():
    verifier = ProvenanceVerifier()
    h1 = verifier.append_event("TriageAgent", "finding_filtered", {"id": "1"})
    h2 = verifier.append_event("PatchAgent", "patch_generated", {"diff": "--- a/b"})
    h3 = verifier.append_event("VerifierAgent", "test_passed", {"stdout": "OK"})

    assert len(verifier.chain) == 3
    assert verifier.verify_integrity() is True
    assert h1 != h2 != h3


def test_provenance_verifier_tamper_detection():
    verifier = ProvenanceVerifier()
    verifier.append_event("TriageAgent", "triage", {"id": "1"})
    verifier.append_event("PatchAgent", "patch", {"id": "1"})

    # Intentionally corrupt the chain
    verifier.chain[1]["prev_hash"] = "corrupted_hash_value"
    assert verifier.verify_integrity() is False
