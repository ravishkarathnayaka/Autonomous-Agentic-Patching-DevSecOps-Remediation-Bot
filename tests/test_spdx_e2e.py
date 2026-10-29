import json
import pytest
from agent_engine.tools.spdx_generator import SPDXGenerator


def test_spdx_generator_e2e_spec():
    """Verify SPDX 2.3 generator produces standard-compliant SBOM structure."""
    packages = [
        {"name": "requests", "version": "2.31.0", "license": "Apache-2.0", "purl": "pkg:pypi/requests@2.31.0"},
        {"name": "urllib3", "version": "2.0.7", "license": "MIT", "purl": "pkg:pypi/urllib3@2.0.7"},
        {"name": "cryptography", "version": "41.0.5", "license": "Apache-2.0", "purl": "pkg:pypi/cryptography@41.0.5"}
    ]

    sbom = SPDXGenerator.generate_sbom(
        project_name="devsecops-bot-core",
        packages=packages,
        document_namespace="https://remediation.devsecops.io/spdx/core-v1"
    )

    # 1. Document Level
    assert sbom["spdxVersion"] == "SPDX-2.3"
    assert sbom["dataLicense"] == "CC0-1.0"
    assert sbom["SPDXID"] == "SPDXRef-DOCUMENT"
    assert sbom["name"] == "devsecops-bot-core SBOM"
    assert sbom["documentNamespace"] == "https://remediation.devsecops.io/spdx/core-v1"
    assert "creationInfo" in sbom
    assert "created" in sbom["creationInfo"]

    # 2. Package Level (1 root package + 3 dependency packages = 4 total)
    assert len(sbom["packages"]) == 4
    root_pkg = sbom["packages"][0]
    assert root_pkg["name"] == "devsecops-bot-core"
    assert root_pkg["SPDXID"] == "SPDXRef-Package-devsecops-bot-core"

    dep_packages = {p["name"]: p for p in sbom["packages"][1:]}
    assert "requests" in dep_packages
    assert dep_packages["requests"]["versionInfo"] == "2.31.0"
    assert dep_packages["requests"]["licenseConcluded"] == "Apache-2.0"
    assert dep_packages["requests"]["externalRefs"][0]["referenceLocator"] == "pkg:pypi/requests@2.31.0"

    # 3. Relationships
    assert len(sbom["relationships"]) == 4
    rel_types = [r["relationshipType"] for r in sbom["relationships"]]
    assert "DESCRIBES" in rel_types
    assert rel_types.count("DEPENDS_ON") == 3

    # 4. JSON Serialization Integrity
    raw_json = json.dumps(sbom)
    deserialized = json.loads(raw_json)
    assert deserialized == sbom
