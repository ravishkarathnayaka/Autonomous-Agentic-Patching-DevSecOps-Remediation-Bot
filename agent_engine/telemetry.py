"""Telemetry and remediation metrics tracker for DevSecOps reporting."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class RemediationMetric:
    """Individual finding remediation attempt metrics."""
    finding_id: str
    rule_id: str
    severity: str
    cwe: List[str]
    start_time: str
    end_time: str
    duration_seconds: float
    status: str
    retry_count: int
    sandbox_passed: bool
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class TelemetryReport:
    """Aggregated session metrics report."""
    total_findings: int = 0
    successful_patches: int = 0
    failed_patches: int = 0
    total_retries: int = 0
    average_duration_seconds: float = 0.0
    metrics: List[RemediationMetric] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics summary to serializable dictionary."""
        return {
            "summary": {
                "total_findings": self.total_findings,
                "successful_patches": self.successful_patches,
                "failed_patches": self.failed_patches,
                "success_rate_percent": (
                    round((self.successful_patches / self.total_findings) * 100, 1)
                    if self.total_findings > 0 else 0.0
                ),
                "total_retries": self.total_retries,
                "average_duration_seconds": round(self.average_duration_seconds, 2)
            },
            "records": [m.__dict__ for m in self.metrics]
        }

    def export_json(self, output_path: Path) -> None:
        """Write metrics summary to JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)


class TelemetryTracker:
    """Tracks and computes aggregated DevSecOps remediation metrics."""

    def __init__(self) -> None:
        self.metrics: List[RemediationMetric] = []

    def record_attempt(
        self,
        finding_id: str,
        rule_id: str,
        severity: str,
        cwe: List[str],
        duration_seconds: float,
        status: str,
        retry_count: int,
        sandbox_passed: bool,
        prompt_tokens: int = 0,
        completion_tokens: int = 0
    ) -> None:
        """Record an individual remediation event."""
        now = datetime.now(timezone.utc).isoformat()
        metric = RemediationMetric(
            finding_id=finding_id,
            rule_id=rule_id,
            severity=severity,
            cwe=cwe,
            start_time=now,
            end_time=now,
            duration_seconds=duration_seconds,
            status=status,
            retry_count=retry_count,
            sandbox_passed=sandbox_passed,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens
        )
        self.metrics.append(metric)

    def generate_report(self) -> TelemetryReport:
        """Calculate summary statistics across all recorded remediation events."""
        total = len(self.metrics)
        successes = sum(1 for m in self.metrics if m.status == "PR_READY" or m.sandbox_passed)
        fails = total - successes
        retries = sum(m.retry_count for m in self.metrics)
        avg_dur = sum(m.duration_seconds for m in self.metrics) / total if total > 0 else 0.0

        return TelemetryReport(
            total_findings=total,
            successful_patches=successes,
            failed_patches=fails,
            total_retries=retries,
            average_duration_seconds=avg_dur,
            metrics=self.metrics
        )
