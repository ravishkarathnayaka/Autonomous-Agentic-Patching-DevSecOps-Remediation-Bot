"""SPDX 2.3 JSON Software Bill of Materials (SBOM) generator."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import uuid


class SPDXGenerator:
    """Generates standardized SPDX 2.3 JSON Software Bill of Materials for software supply chain security."""

    @classmethod
    def generate_sbom(
        cls,
        project_name: str,
        packages: List[Dict[str, str]],
        document_namespace: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate an SPDX 2.3 JSON SBOM document from a list of packages.

        Args:
            project_name: Name of the root repository/project.
            packages: List of dicts with `name`, `version`, optional `license`, `purl`.
            document_namespace: Optional unique URI namespace.

        Returns:
            Dict conforming to SPDX 2.3 JSON schema specification.
        """
        doc_uuid = str(uuid.uuid4())
        namespace = document_namespace or f"https://spdx.org/spdxdocs/{project_name}-{doc_uuid}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        root_spdx_id = f"SPDXRef-Package-{project_name.replace(' ', '-').replace('_', '-')}"

        spdx_packages: List[Dict[str, Any]] = [
            {
                "SPDXID": root_spdx_id,
                "name": project_name,
                "versionInfo": "1.0.0",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT"
            }
        ]

        relationships: List[Dict[str, Any]] = [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": root_spdx_id,
                "relationshipType": "DESCRIBES"
            }
        ]

        for pkg in packages:
            p_name = pkg.get("name", "unknown")
            p_version = pkg.get("version", "0.0.0")
            p_license = pkg.get("license", "NOASSERTION")
            pkg_spdx_id = f"SPDXRef-Package-{p_name.replace('_', '-').lower()}-{p_version.replace('.', '-')}"

            spdx_pkg = {
                "SPDXID": pkg_spdx_id,
                "name": p_name,
                "versionInfo": p_version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": p_license,
                "licenseDeclared": p_license,
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": pkg.get("purl", f"pkg:generic/{p_name}@{p_version}")
                    }
                ]
            }
            spdx_packages.append(spdx_pkg)

            relationships.append({
                "spdxElementId": root_spdx_id,
                "relatedSpdxElement": pkg_spdx_id,
                "relationshipType": "DEPENDS_ON"
            })

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"{project_name} SBOM",
            "documentNamespace": namespace,
            "creationInfo": {
                "created": now_iso,
                "creators": ["Tool: Autonomous-Agentic-Patching-Bot-2.0"]
            },
            "packages": spdx_packages,
            "relationships": relationships
        }
