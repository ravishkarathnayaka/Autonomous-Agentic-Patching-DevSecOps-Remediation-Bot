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

    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url

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

    def _build_payload(self, title: str, color: str, fields: list) -> Dict[str, Any]:
        """Build universal webhook payload compatible with Discord and Slack webhooks."""
        return {
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
