"""Collective Team Notification & Alert Dispatcher for DataGuard.

Dispatches formatted operational alerts (Console, Slack/Teams Webhook payloads,
and Email simulations) across on-call channels when incidents, SLA breaches,
or recovery requests occur.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class AlertNotification:
    notification_id: str
    channel: str  # 'SLACK', 'EMAIL', 'PAGERDUTY', 'CONSOLE'
    severity: str  # 'P1', 'P2', 'P3', 'P4'
    title: str
    message: str
    timestamp: str
    metadata: Dict[str, Any]


class NotificationDispatcher:
    """Dispatches and tracks collective team alerts."""

    def __init__(self):
        # Keeps in-memory buffer of recent sent notifications (for UI and testing)
        self.sent_notifications: List[AlertNotification] = []

    def dispatch_incident_alert(
        self,
        incident_code: str,
        pipeline_id: str,
        severity: str,
        title: str,
        root_cause: str,
        downstream_impact: str,
        owner_email: str,
    ) -> AlertNotification:
        """Dispatches an urgent incident alert to the team."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        notif_id = f"NOTIF-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.sent_notifications) + 1}"

        severity_emoji = {"P1": "🔴 CRITICAL", "P2": "🟠 HIGH", "P3": "🟡 MEDIUM", "P4": "🔵 LOW"}.get(
            severity, "⚪ INFO"
        )

        formatted_msg = (
            f"[{severity_emoji}] Incident {incident_code} - Pipeline '{pipeline_id}'\n"
            f"Summary: {title}\n"
            f"Root Cause: {root_cause}\n"
            f"Blast Radius: {downstream_impact}\n"
            f"Assigned Channel: {owner_email}"
        )

        notification = AlertNotification(
            notification_id=notif_id,
            channel="SLACK",
            severity=severity,
            title=title,
            message=formatted_msg,
            timestamp=now,
            metadata={
                "incident_code": incident_code,
                "pipeline_id": pipeline_id,
                "owner_email": owner_email,
            },
        )

        self.sent_notifications.append(notification)
        return notification

    def dispatch_sla_breach_alert(
        self,
        pipeline_id: str,
        sla_seconds: int,
        actual_duration_seconds: float,
        overage_percent: float,
    ) -> AlertNotification:
        """Dispatches an alert when a pipeline exceeds its SLA latency budget."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        notif_id = f"NOTIF-SLA-{datetime.now().strftime('%Y%m%d%H%M%S')}-{len(self.sent_notifications) + 1}"

        title = f"⚠️ SLA Breach: '{pipeline_id}' exceeded budget by {overage_percent}%"
        msg = (
            f"[SLA BREACH ALERT] Pipeline '{pipeline_id}'\n"
            f"Configured SLA: {sla_seconds}s | Actual Duration: {actual_duration_seconds:.1f}s\n"
            f"Latency Overage: {overage_percent}%\n"
            f"Recommendation: Review database lock contention or upstream delay."
        )

        notification = AlertNotification(
            notification_id=notif_id,
            channel="PAGERDUTY",
            severity="P2" if overage_percent < 100 else "P1",
            title=title,
            message=msg,
            timestamp=now,
            metadata={
                "pipeline_id": pipeline_id,
                "sla_seconds": sla_seconds,
                "duration_seconds": actual_duration_seconds,
            },
        )

        self.sent_notifications.append(notification)
        return notification

    def get_recent_notifications(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns the most recent dispatched notifications."""
        return [asdict(n) for n in reversed(self.sent_notifications[-limit:])]
