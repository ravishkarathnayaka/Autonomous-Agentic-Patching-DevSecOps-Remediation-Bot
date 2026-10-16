"""
NIST National Vulnerability Database (NVD) API v2 Client
Enriches CVE identifiers with official CVSS metrics, CWE classifications,
vulnerability descriptions, and remediation references from NIST.
"""

from typing import Dict, Any, Optional
import urllib.request
import urllib.error
import json
import logging

logger = logging.getLogger(__name__)


class NVDClient:
    """
    Client for querying the NIST NVD CVE API (API v2.0).
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 10):
        self.api_key = api_key
        self.timeout = timeout

    def build_url(self, cve_id: str) -> str:
        """Construct the NVD REST query URL for a specific CVE ID."""
        clean_cve = cve_id.strip().upper()
        return f"{self.BASE_URL}?cveId={clean_cve}"

    def parse_cve_response(self, response_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse raw NVD API JSON response into normalized security metadata.
        """
        vulnerabilities = response_data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_item = vulnerabilities[0].get("cve", {})
        cve_id = cve_item.get("id", "")

        # Extract primary English description
        descriptions = cve_item.get("descriptions", [])
        desc_text = ""
        for d in descriptions:
            if d.get("lang") == "en":
                desc_text = d.get("value", "")
                break

        # Extract CVSS v3.1 or v3.0 metrics
        metrics = cve_item.get("metrics", {})
        cvss_data = {}
        for metric_key in ["cvssMetricV31", "cvssMetricV30"]:
            if metric_key in metrics and metrics[metric_key]:
                primary_metric = metrics[metric_key][0]
                cvss_data = primary_metric.get("cvssData", {})
                break

        base_score = cvss_data.get("baseScore", 0.0)
        severity = cvss_data.get("baseSeverity", "UNKNOWN")
        vector_string = cvss_data.get("vectorString", "")

        # Extract CWE IDs
        cwes = []
        for weakness in cve_item.get("weaknesses", []):
            for desc in weakness.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)

        # Extract references
        refs = [r.get("url") for r in cve_item.get("references", []) if r.get("url")]

        return {
            "cve_id": cve_id,
            "description": desc_text,
            "cvss_score": float(base_score),
            "severity": severity,
            "vector_string": vector_string,
            "cwes": cwes,
            "references": refs[:5],
            "published": cve_item.get("published", "")
        }

    def fetch_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Perform HTTP request to query NVD API for a CVE.
        Handles rate limits and returns None on failure or missing CVE.
        """
        url = self.build_url(cve_id)
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Autonomous-Agentic-Patching-Bot/1.0")
        if self.api_key:
            req.add_header("apiKey", self.api_key)

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return self.parse_cve_response(data)
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError) as e:
            logger.warning(f"Failed to fetch {cve_id} from NVD: {e}")
            return None
