from agent_engine.tools.cyclonedx_generator import CycloneDXGenerator


def test_cyclonedx_generator():
    packages = [
        {"name": "flask", "version": "3.0.0", "license": "BSD-3-Clause", "purl": "pkg:pypi/flask@3.0.0"},
        {"name": "requests", "version": "2.31.0", "license": "Apache-2.0", "purl": "pkg:pypi/requests@2.31.0"}
    ]

    bom = CycloneDXGenerator.generate_sbom(
        project_name="payment-gateway",
        packages=packages,
        serial_number="urn:uuid:12345678-1234-5678-1234-567812345678"
    )

    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == "1.5"
    assert bom["serialNumber"] == "urn:uuid:12345678-1234-5678-1234-567812345678"
    assert bom["metadata"]["component"]["name"] == "payment-gateway"
    assert len(bom["components"]) == 2
    assert bom["components"][0]["name"] == "flask"
    assert bom["components"][0]["version"] == "3.0.0"
    assert bom["components"][0]["licenses"][0]["license"]["id"] == "BSD-3-Clause"
