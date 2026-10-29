from agent_engine.tools.pagerduty_events import PagerDutyEventFormatter


def test_pagerduty_trigger_event():
    event = PagerDutyEventFormatter.format_trigger_event(
        routing_key="pd-integration-key-12345",
        vuln_id="CVE-2024-9999",
        severity="CRITICAL",
        source="security-scanner",
        description="Remote code execution identified in dependencies",
        custom_details={"cwe": "CWE-78", "cvss": 9.8}
    )

    assert event["event_action"] == "trigger"
    assert event["dedup_key"] == "devsecops-cve-2024-9999"
    assert event["payload"]["severity"] == "critical"
    assert event["payload"]["custom_details"]["cwe"] == "CWE-78"


def test_pagerduty_resolve_event():
    event = PagerDutyEventFormatter.format_resolve_event(
        routing_key="pd-integration-key-12345",
        vuln_id="CVE-2024-9999"
    )

    assert event["event_action"] == "resolve"
    assert event["dedup_key"] == "devsecops-cve-2024-9999"
