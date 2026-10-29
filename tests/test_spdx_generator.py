from agent_engine.tools.spdx_generator import SPDXGenerator


def test_generate_spdx_sbom():
    packages = [
        {"name": "flask", "version": "2.2.5", "license": "BSD-3-Clause", "purl": "pkg:pypi/flask@2.2.5"},
        {"name": "requests", "version": "2.31.0", "license": "Apache-2.0"}
    ]

    sbom = SPDXGenerator.generate_sbom("enterprise-app", packages)

    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["dataLicense"] == "CC0-1.0"
    assert len(sbom["packages"]) == 3  # Root package + 2 dependencies
    assert len(sbom["relationships"]) == 3

    # Check dependency relationship
    depends_rels = [r for r in sbom["relationships"] if r["relationshipType"] == "DEPENDS_ON"]
    assert len(depends_rels) == 2
