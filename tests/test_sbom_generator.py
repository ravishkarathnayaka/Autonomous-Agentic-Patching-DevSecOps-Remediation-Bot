from agent_engine.tools.sbom_generator import generate_cyclonedx_sbom


def test_generate_cyclonedx_sbom():
    deps = [
        {"name": "Flask", "version": "2.2.5"},
        {"name": "Werkzeug", "version": "2.2.3"}
    ]
    sbom = generate_cyclonedx_sbom(deps, project_name="my-service")

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert len(sbom["components"]) == 2
    assert sbom["components"][0]["name"] == "Flask"
    assert sbom["components"][0]["purl"] == "pkg:pypi/Flask@2.2.5"
