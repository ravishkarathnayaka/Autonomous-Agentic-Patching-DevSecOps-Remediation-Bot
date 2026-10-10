import pytest
from agent_engine.tools.notification_dispatcher import NotificationDispatcher


def test_build_teams_payload():
    dispatcher = NotificationDispatcher(channel="teams")
    payload = dispatcher.build_teams_payload(
        title="Security Alert",
        color="#22c55e",
        fields=[{"name": "Rule", "value": "CWE-89"}]
    )
    assert payload["@type"] == "MessageCard"
    assert payload["themeColor"] == "22c55e"
    assert payload["title"] == "Security Alert"
    assert len(payload["sections"][0]["facts"]) == 1
    assert payload["sections"][0]["facts"][0]["name"] == "Rule"


def test_build_universal_payload_teams_mode():
    dispatcher = NotificationDispatcher(channel="teams")
    payload = dispatcher._build_payload(
        title="Alert",
        color="#ef4444",
        fields=[{"name": "Status", "value": "Failed"}]
    )
    assert payload["@type"] == "MessageCard"


def test_build_universal_payload_auto_mode():
    dispatcher = NotificationDispatcher(channel="auto")
    payload = dispatcher._build_payload(
        title="Alert",
        color="#22c55e",
        fields=[{"name": "Status", "value": "Success"}]
    )
    assert "attachments" in payload
    assert "embeds" in payload
    assert "@type" in payload
