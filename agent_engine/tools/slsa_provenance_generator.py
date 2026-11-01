"""SLSA Level 3 in-toto provenance attestation predicate generator."""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional


class SLSAProvenanceGenerator:
    """Generates standard in-toto SLSA Provenance v0.2/v1.0 attestation predicates."""

    @classmethod
    def generate_provenance(
        cls,
        artifact_name: str,
        artifact_bytes: bytes,
        repo_uri: str,
        commit_sha: str,
        builder_id: str = "https://github.com/actions/runner@v3",
        materials: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """Generate an in-toto SLSA Provenance statement.

        Args:
            artifact_name: Filename or target container image name.
            artifact_bytes: Raw bytes to compute cryptographic sha256.
            repo_uri: Source code git repository URL.
            commit_sha: Verified git commit hash.
            builder_id: URI identifying build platform or runner.
            materials: Optional list of upstream dependencies or parent images.

        Returns:
            Dict conforming to in-toto Statement / SLSA Provenance specification.
        """
        sha256_hash = hashlib.sha256(artifact_bytes).hexdigest()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        mat_list = materials or [
            {
                "uri": repo_uri,
                "digest": {"sha1": commit_sha}
            }
        ]

        return {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": [
                {
                    "name": artifact_name,
                    "digest": {
                        "sha256": sha256_hash
                    }
                }
            ],
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "predicate": {
                "builder": {
                    "id": builder_id
                },
                "buildType": "https://actions.github.io/buildtypes/v1/run",
                "invocation": {
                    "configSource": {
                        "uri": repo_uri,
                        "digest": {
                            "sha1": commit_sha
                        },
                        "entryPoint": ".github/workflows/remediation.yml"
                    }
                },
                "metadata": {
                    "buildInvocationId": f"build-{commit_sha[:8]}",
                    "buildStartedOn": now_iso,
                    "completeness": {
                        "parameters": True,
                        "environment": True,
                        "materials": True
                    },
                    "reproducible": True
                },
                "materials": mat_list
            }
        }
