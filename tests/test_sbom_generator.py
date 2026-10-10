import pytest
from agent_engine.tools.sbom_generator import SBOMGenerator


def test_parse_requirements():
    content = """# Comment\nflask==2.0.1\nrequests>=2.25.0\npytest\n"""
    pkgs = SBOMGenerator.parse_requirements(content)
    assert len(pkgs) == 3
    assert pkgs[0] == {"name": "flask", "version": "2.0.1"}
    assert pkgs[1] == {"name": "requests", "version": "2.25.0"}
    assert pkgs[2] == {"name": "pytest", "version": "latest"}


def test_generate_cyclonedx_sbom():
    content = "flask==2.0.1\nrequests==2.31.0\n"
    sbom = SBOMGenerator.generate_cyclonedx_sbom("test-service", content, "2.1.0")

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["metadata"]["component"]["name"] == "test-service"
    assert len(sbom["components"]) == 2

    flask_comp = sbom["components"][0]
    assert flask_comp["name"] == "flask"
    assert flask_comp["version"] == "2.0.1"
    assert flask_comp["purl"] == "pkg:pypi/flask@2.0.1"
