"""CycloneDX 1.5 JSON Software Bill of Materials (SBOM) generator."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid


class CycloneDXGenerator:
    """Generates standardized CycloneDX 1.5 JSON Software Bill of Materials."""

    @classmethod
    def generate_sbom(
        cls,
        project_name: str,
        packages: List[Dict[str, str]],
        serial_number: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate a CycloneDX 1.5 JSON SBOM document from a list of packages.

        Args:
            project_name: Root application/repository name.
            packages: List of packages with `name`, `version`, optional `license`, `purl`.
            serial_number: Optional URN serial number.

        Returns:
            Dict conforming to CycloneDX 1.5 JSON schema.
        """
        bom_serial = serial_number or f"urn:uuid:{uuid.uuid4()}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        components: List[Dict[str, Any]] = []
        for pkg in packages:
            name = pkg.get("name", "unknown")
            version = pkg.get("version", "0.0.0")
            lic = pkg.get("license", "MIT")
            purl = pkg.get("purl", f"pkg:generic/{name}@{version}")

            components.append({
                "type": "library",
                "bom-ref": f"{name}@{version}",
                "name": name,
                "version": version,
                "purl": purl,
                "licenses": [
                    {
                        "license": {
                            "id": lic
                        }
                    }
                ]
            })

        return {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": bom_serial,
            "version": 1,
            "metadata": {
                "timestamp": now_iso,
                "tools": [
                    {
                        "vendor": "Autonomous-DevSecOps",
                        "name": "Remediation-Bot",
                        "version": "2.0.0"
                    }
                ],
                "component": {
                    "type": "application",
                    "bom-ref": f"{project_name}@1.0.0",
                    "name": project_name,
                    "version": "1.0.0"
                }
            },
            "components": components
        }
