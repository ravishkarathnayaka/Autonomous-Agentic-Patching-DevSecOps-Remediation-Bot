"""Software Bill of Materials (SBOM) generator conforming to CycloneDX 1.5 JSON specification."""

import json
import uuid
from typing import Dict, List


def generate_cyclonedx_sbom(
    dependencies: List[Dict[str, str]],
    project_name: str = "target_repo",
    project_version: str = "1.0.0"
) -> Dict[str, any]:
    """Produce CycloneDX 1.5 JSON SBOM document from dependency list.

    Args:
        dependencies: List of dicts with 'name' and 'version' keys.
        project_name: Application name.
        project_version: Application release version.

    Returns:
        CycloneDX 1.5 JSON dictionary.
    """
    components = []
    for dep in dependencies:
        pkg_name = dep.get("name", "unknown")
        pkg_ver = dep.get("version", "0.0.0")
        components.append({
            "type": "library",
            "name": pkg_name,
            "version": pkg_ver,
            "purl": f"pkg:pypi/{pkg_name}@{pkg_ver}",
            "scope": "required"
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": project_name,
                "version": project_version
            }
        },
        "components": components
    }
