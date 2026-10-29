"""Google OSV.dev (Open Source Vulnerabilities) API v1 client for cross-ecosystem advisory enrichment."""

import json
import logging
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

logger = logging.getLogger(__name__)


class OSVClient:
    """Client for querying the OSV.dev open vulnerability database."""

    BASE_URL = "https://api.osv.dev/v1/query"

    def __init__(self, timeout: int = 5):
        self.timeout = timeout

    def build_payload(self, package_name: str, version: str, ecosystem: str = "PyPI") -> Dict[str, Any]:
        """Construct the OSV query JSON payload."""
        return {
            "version": version,
            "package": {
                "name": package_name,
                "ecosystem": ecosystem
            }
        }

    def parse_vuln_response(self, response_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse raw OSV API JSON into normalized advisory records.

        Args:
            response_data: Parsed OSV response dict.

        Returns:
            List of parsed vulnerability summaries.
        """
        vulns = response_data.get("vulns", [])
        results: List[Dict[str, Any]] = []

        for v in vulns:
            v_id = v.get("id", "")
            summary = v.get("summary", v.get("details", "OSV Security Advisory"))
            aliases = v.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE-")), v_id)

            fixed_versions = []
            for affected in v.get("affected", []):
                for r in affected.get("ranges", []):
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_versions.append(event["fixed"])

            results.append({
                "osv_id": v_id,
                "cve_id": cve_id,
                "summary": summary[:200],
                "aliases": aliases,
                "fixed_versions": list(set(fixed_versions)),
                "database_specific": v.get("database_specific", {})
            })

        return results

    def query_package(self, package_name: str, version: str, ecosystem: str = "PyPI") -> Optional[List[Dict[str, Any]]]:
        """Query OSV API over HTTP with error handling."""
        payload = json.dumps(self.build_payload(package_name, version, ecosystem)).encode("utf-8")
        req = urllib.request.Request(
            self.BASE_URL,
            data=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Autonomous-Patching-Bot/2.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return self.parse_vuln_response(data)
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as e:
            logger.warning("OSV.dev query error for %s@%s: %s", package_name, version, e)
            return None
