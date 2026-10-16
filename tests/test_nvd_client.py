"""
Unit tests for NVDClient.
"""

from agent_engine.tools.nvd_client import NVDClient


def test_nvd_client_build_url():
    client = NVDClient()
    url = client.build_url("cve-2023-44487")
    assert url == "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2023-44487"


def test_nvd_client_parse_cve_response():
    sample_response = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-38545",
                    "descriptions": [
                        {"lang": "en", "value": "SOCKS5 heap buffer overflow in curl."}
                    ],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "version": "3.1",
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "baseScore": 9.8,
                                    "baseSeverity": "CRITICAL"
                                }
                            }
                        ]
                    },
                    "weaknesses": [
                        {
                            "description": [
                                {"lang": "en", "value": "CWE-122"}
                            ]
                        }
                    ],
                    "references": [
                        {"url": "https://curl.se/docs/CVE-2023-38545.html"}
                    ],
                    "published": "2023-10-18T14:15:00.000"
                }
            }
        ]
    }

    client = NVDClient()
    parsed = client.parse_cve_response(sample_response)

    assert parsed is not None
    assert parsed["cve_id"] == "CVE-2023-38545"
    assert parsed["cvss_score"] == 9.8
    assert parsed["severity"] == "CRITICAL"
    assert "CWE-122" in parsed["cwes"]
    assert "curl" in parsed["description"]
    assert len(parsed["references"]) == 1


def test_nvd_client_parse_empty():
    client = NVDClient()
    assert client.parse_cve_response({"vulnerabilities": []}) is None
