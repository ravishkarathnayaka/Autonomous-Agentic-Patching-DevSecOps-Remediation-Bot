from agent_engine.tools.osv_client import OSVClient


def test_osv_client_build_payload():
    client = OSVClient()
    payload = client.build_payload("jinja2", "2.10", "PyPI")
    assert payload["version"] == "2.10"
    assert payload["package"]["name"] == "jinja2"
    assert payload["package"]["ecosystem"] == "PyPI"


def test_osv_client_parse_response():
    sample_response = {
        "vulns": [
            {
                "id": "GHSA-g3rq-g295-48cu",
                "summary": "Sandbox breakout in Jinja2",
                "aliases": ["CVE-2019-10906"],
                "affected": [
                    {
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "2.10.1"}]
                            }
                        ]
                    }
                ]
            }
        ]
    }

    client = OSVClient()
    parsed = client.parse_vuln_response(sample_response)

    assert len(parsed) == 1
    assert parsed[0]["cve_id"] == "CVE-2019-10906"
    assert "2.10.1" in parsed[0]["fixed_versions"]
    assert "Sandbox breakout" in parsed[0]["summary"]
