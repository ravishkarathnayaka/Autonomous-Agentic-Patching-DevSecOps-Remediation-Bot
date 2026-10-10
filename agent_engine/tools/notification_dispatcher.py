"""Webhook notification dispatcher for Slack, Discord, and Teams alerts."""

import json
import logging
from typing import Any, Dict, Optional
import urllib.error
import urllib.request

from agent_engine.state import Finding, RemediationState, RemediationStatus

logger = logging.getLogger(__name__)


class NotificationDispatcher:
    """Dispatches webhook alerts for security remediation events."""

    def __init__(self, webhook_url: Optional[str] = None, channel: str = "auto"):
        self.webhook_url = webhook_url
        self.channel = channel.lower()

    def dispatch_pr_created(self, state: RemediationState) -> bool:
        """Send notification when Pull Request is generated."""
        if not self.webhook_url:
            logger.debug("No webhook URL configured; skipping notification.")
            return False

        finding = state.finding
        payload = self._build_payload(
            title="🛡️ Autonomous Security Patch Verified & PR Ready",
            color="#22c55e",  # Green
            fields=[
                {"name": "Vulnerability", "value": finding.title, "inline": False},
                {"name": "Rule ID", "value": finding.rule_id, "inline": True},
                {"name": "Severity", "value": finding.severity.value, "inline": True},
                {"name": "File", "value": f"`{finding.file_path}:{finding.start_line}`", "inline": True},
                {"name": "Branch", "value": f"`{state.pr_branch or 'N/A'}`", "inline": True},
                {"name": "Retries", "value": str(state.retry_count), "inline": True}
            ]
        )
        return self._send_webhook(payload)

    def dispatch_remediation_failed(self, state: RemediationState) -> bool:
        """Send notification when remediation exceeds retry limit or fails."""
        if not self.webhook_url:
            return False

        finding = state.finding
        payload = self._build_payload(
            title="⚠️ Autonomous Remediation Failed (Manual Review Required)",
            color="#ef4444",  # Red
            fields=[
                {"name": "Vulnerability", "value": finding.title, "inline": False},
                {"name": "Rule ID", "value": finding.rule_id, "inline": True},
                {"name": "Error Trace", "value": f"```{state.last_error_trace or 'Unknown error'}```", "inline": False}
            ]
        )
        return self._send_webhook(payload)

    def build_teams_payload(self, title: str, color: str, fields: list) -> Dict[str, Any]:
        """Build Microsoft Teams Office 365 Connector card payload."""
        facts = [{"name": f["name"], "value": f["value"]} for f in fields]
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": title,
            "themeColor": color.lstrip("#"),
            "title": title,
            "sections": [
                {
                    "activityTitle": "Autonomous Remediation Bot",
                    "facts": facts,
                    "markdown": True
                }
            ]
        }

    def _build_payload(self, title: str, color: str, fields: list) -> Dict[str, Any]:
        """Build universal webhook payload compatible with Discord, Slack, and Microsoft Teams."""
        if self.channel == "teams":
            return self.build_teams_payload(title, color, fields)

        payload: Dict[str, Any] = {
            "text": title,
            "attachments": [
                {
                    "title": title,
                    "color": color,
                    "fields": [{"title": f["name"], "value": f["value"], "short": f.get("inline", False)} for f in fields]
                }
            ],
            # Discord embeds fallback
            "embeds": [
                {
                    "title": title,
                    "color": int(color.lstrip("#"), 16),
                    "fields": fields
                }
            ]
        }
        if self.channel == "auto":
            payload.update({
                "@type": "MessageCard",
                "@context": "https://schema.org/extensions",
                "summary": title,
                "themeColor": color.lstrip("#"),
                "sections": [{"facts": [{"name": f["name"], "value": f["value"]} for f in fields]}]
            })
        return payload

    def _send_webhook(self, payload: Dict[str, Any]) -> bool:
        """Execute HTTP POST to webhook endpoint."""
        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json", "User-Agent": "Autonomous-DevSecOps-Bot"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 204)
        except Exception as e:
            logger.warning("Failed to send webhook notification: %s", e)
            return False
