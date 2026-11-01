import hashlib
from agent_engine.tools.slsa_provenance_generator import SLSAProvenanceGenerator


def test_slsa_provenance_generation():
    artifact_content = b"console.log('Remediated build artifact');\n"
    expected_hash = hashlib.sha256(artifact_content).hexdigest()

    prov = SLSAProvenanceGenerator.generate_provenance(
        artifact_name="bundle.min.js",
        artifact_bytes=artifact_content,
        repo_uri="https://github.com/organization/target-repo",
        commit_sha="a1b2c3d4e5f67890123456789abcdef012345678"
    )

    assert prov["_type"] == "https://in-toto.io/Statement/v0.1"
    assert prov["predicateType"] == "https://slsa.dev/provenance/v0.2"
    assert prov["subject"][0]["name"] == "bundle.min.js"
    assert prov["subject"][0]["digest"]["sha256"] == expected_hash
    assert prov["predicate"]["invocation"]["configSource"]["digest"]["sha1"] == "a1b2c3d4e5f67890123456789abcdef012345678"
    assert len(prov["predicate"]["materials"]) == 1
