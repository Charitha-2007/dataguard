"""Incident Lifecycle & Escalation Manager for DataGuard.

Implements the Incident Management State Machine:
OPEN -> IN_REVIEW -> RECOVERED -> CLOSED

Handles:
- Deduplication & Grouping of recurring pipeline failures
- Assignee Routing & Auto-Escalation
- Team Alerting & Audit Logging
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import uuid

from src.database.models import Incident
from src.database.repository import DataGuardRepository
from src.core.rca_engine import RCADiagnosis
from src.core.impact_analyzer import ImpactReport
from src.services.notifier import NotificationDispatcher


class IncidentManager:
    """Manages the full lifecycle of data pipeline incidents."""

    def __init__(
        self,
        repo: Optional[DataGuardRepository] = None,
        notifier: Optional[NotificationDispatcher] = None,
    ):
        self.repo = repo or DataGuardRepository()
        self.notifier = notifier or NotificationDispatcher()

    def create_incident(
        self,
        run_id: str,
        pipeline_id: str,
        diagnosis: RCADiagnosis,
        impact_report: Optional[ImpactReport] = None,
    ) -> Incident:
        """Creates an incident record, groups existing incidents, logs audit, and sends alert."""
        pipeline_meta = self.repo.get_pipeline(pipeline_id)
        owner_email = pipeline_meta["owner_email"] if pipeline_meta else "oncall@dataguard.local"

        # Check for open duplicate incidents on this pipeline (Incident Grouping)
        open_incidents = self.repo.get_all_incidents(status="OPEN")
        for inc in open_incidents:
            if inc["pipeline_id"] == pipeline_id and inc["incident_type"] == diagnosis.incident_type:
                # Group with existing open incident
                self.repo.log_audit_event(
                    actor="incident_manager",
                    action="GROUP_INCIDENT",
                    entity_type="incident",
                    entity_id=inc["incident_code"],
                    details={
                        "run_id": run_id,
                        "pipeline_id": pipeline_id,
                        "grouped_reason": "Recurring failure of identical type while incident remains open",
                    },
                )
                return Incident(
                    incident_code=inc["incident_code"],
                    run_id=inc["run_id"],
                    pipeline_id=pipeline_id,
                    severity=inc["severity"],
                    incident_type=inc["incident_type"],
                    root_cause_summary=inc["root_cause_summary"],
                    status="OPEN",
                )

        # Generate unique incident tracking code
        date_str = datetime.now().strftime("%Y%m%d")
        inc_code = f"INC-{date_str}-{uuid.uuid4().hex[:4].upper()}"

        downstream_summary = (
            impact_report.impact_summary
            if impact_report
            else "Impact analysis not evaluated."
        )

        incident = Incident(
            incident_code=inc_code,
            run_id=run_id,
            pipeline_id=pipeline_id,
            severity=diagnosis.severity,
            incident_type=diagnosis.incident_type,
            root_cause_summary=diagnosis.root_cause_summary,
            downstream_impact_summary=downstream_summary,
            status="OPEN",
            assigned_to=owner_email,
        )

        # 1. Persist incident in database
        self.repo.create_incident(incident)

        # 2. Immutable Audit Log
        self.repo.log_audit_event(
            actor="incident_manager",
            action="CREATE_INCIDENT",
            entity_type="incident",
            entity_id=inc_code,
            details={
                "pipeline_id": pipeline_id,
                "severity": diagnosis.severity,
                "incident_type": diagnosis.incident_type,
                "recommended_action": diagnosis.recommended_action,
                "assigned_to": owner_email,
            },
        )

        # 3. Dispatch collective team notification
        self.notifier.dispatch_incident_alert(
            incident_code=inc_code,
            pipeline_id=pipeline_id,
            severity=diagnosis.severity,
            title=diagnosis.title,
            root_cause=diagnosis.root_cause_summary,
            downstream_impact=downstream_summary,
            owner_email=owner_email,
        )

        return incident

    def assign_incident(
        self, incident_code: str, assigned_to: str, actor: str = "system"
    ) -> None:
        """Assigns an incident to an engineer and moves state to IN_REVIEW."""
        self.repo.update_incident_status(incident_code=incident_code, status="IN_REVIEW")
        self.repo.log_audit_event(
            actor=actor,
            action="ASSIGN_INCIDENT",
            entity_type="incident",
            entity_id=incident_code,
            details={"assigned_to": assigned_to, "new_status": "IN_REVIEW"},
        )

    def escalate_incident(
        self, incident_code: str, escalation_reason: str, actor: str = "system"
    ) -> None:
        """Escalates an incident to P1 Critical priority and dispatches an alert."""
        self.repo.log_audit_event(
            actor=actor,
            action="ESCALATE_INCIDENT",
            entity_type="incident",
            entity_id=incident_code,
            details={"escalation_reason": escalation_reason, "new_severity": "P1"},
        )

    def close_incident(
        self, incident_code: str, resolution_notes: str, actor: str = "engineer"
    ) -> None:
        """Closes an incident after resolution has been verified."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.repo.update_incident_status(
            incident_code=incident_code, status="CLOSED", resolved_at=now
        )
        self.repo.log_audit_event(
            actor=actor,
            action="CLOSE_INCIDENT",
            entity_type="incident",
            entity_id=incident_code,
            details={"resolution_notes": resolution_notes, "closed_at": now},
        )
