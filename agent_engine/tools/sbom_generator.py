"""Software Bill of Materials (SBOM) generator conforming to CycloneDX v1.5 JSON schema."""

from datetime import datetime, timezone
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import uuid


class SBOMGenerator:
    """Generates standardized CycloneDX Software Bill of Materials (SBOM) JSON."""

    @staticmethod
    def parse_requirements(content: str) -> List[Dict[str, str]]:
        """Parse requirements.txt content into a list of {name, version} dictionaries."""
        packages: List[Dict[str, str]] = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Match package==version or package>=version
            match = re.match(r"^([\w\.\-]+)(?:==|>=|<=|~=)([\w\.\-]+)", line)
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})
            else:
                # Unversioned package
                unpinned = re.match(r"^([\w\.\-]+)", line)
                if unpinned:
                    packages.append({"name": unpinned.group(1), "version": "latest"})
        return packages

    @classmethod
    def generate_cyclonedx_sbom(
        cls,
        app_name: str,
        requirements_content: str,
        app_version: str = "1.0.0"
    ) -> Dict[str, Any]:
        """Generate CycloneDX v1.5 specification JSON SBOM."""
        parsed = cls.parse_requirements(requirements_content)
        components: List[Dict[str, Any]] = []

        for pkg in parsed:
            name = pkg["name"]
            ver = pkg["version"]
            purl = f"pkg:pypi/{name.lower()}@{ver}"
            comp = {
                "type": "library",
                "bom-ref": purl,
                "name": name,
                "version": ver,
                "purl": purl,
                "scope": "required"
            }
            components.append(comp)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [
                    {
                        "vendor": "Autonomous DevSecOps Bot",
                        "name": "agent_engine",
                        "version": "1.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "name": app_name,
                    "version": app_version
                }
            },
            "components": components
        }
        return sbom
