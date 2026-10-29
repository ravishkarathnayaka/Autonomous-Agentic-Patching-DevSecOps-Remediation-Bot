"""PagerDuty Events API v2 payload generator for critical DevSecOps incident alerting."""

from typing import Any, Dict, Optional


class PagerDutyEventFormatter:
    """Constructs Events API v2 payloads for triggering and resolving PagerDuty security incidents."""

    SEVERITY_MAP = {
        "CRITICAL": "critical",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "info"
    }

    @classmethod
    def format_trigger_event(
        cls,
        routing_key: str,
        vuln_id: str,
        severity: str,
        source: str,
        description: str,
        custom_details: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Construct a trigger incident payload for PagerDuty Events API v2."""
        sev_upper = severity.upper()
        pd_severity = cls.SEVERITY_MAP.get(sev_upper, "warning")
        dedup_key = f"devsecops-{vuln_id.lower()}"

        return {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": f"DevSecOps Alert: {vuln_id} - {description[:120]}",
                "severity": pd_severity,
                "source": source,
                "custom_details": custom_details or {}
            }
        }

    @classmethod
    def format_resolve_event(cls, routing_key: str, vuln_id: str) -> Dict[str, Any]:
        """Construct a resolve incident payload when an autonomous patch is verified."""
        dedup_key = f"devsecops-{vuln_id.lower()}"
        return {
            "routing_key": routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key
        }
