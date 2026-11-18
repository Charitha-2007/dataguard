"""Human-in-the-Loop (HITL) Recovery Approval Gatekeeper for DataGuard.

Enforces Role-Based Access Control (RBAC) on recovery executions:
Prevents automated code/data modifications from executing without explicit
cryptographically audited human sign-off.
"""

from typing import Dict, Any, Optional
import json
from datetime import datetime

from src.database.models import RecoveryAction
from src.database.repository import DataGuardRepository
from src.recovery.recommendation import RecoveryPlan


class ApprovalWorkflowManager:
    """Manages the authorization gate for pipeline remediation actions."""

    def __init__(self, repo: Optional[DataGuardRepository] = None):
        self.repo = repo or DataGuardRepository()

    def submit_recovery_request(
        self,
        incident_code: str,
        pipeline_id: str,
        plan: RecoveryPlan,
        requested_by: str = "ai_recovery_recommender",
    ) -> int:
        """Enqueues a proposed recovery plan awaiting human authorization."""
        action = RecoveryAction(
            incident_code=incident_code,
            pipeline_id=pipeline_id,
            action_type=plan.action_type,
            parameters_json=json.dumps(plan.parameters),
            status="PENDING_APPROVAL",
            requested_by=requested_by,
        )
        action_id = self.repo.create_recovery_action(action)

        # Log audit trail
        self.repo.log_audit_event(
            actor=requested_by,
            action="REQUEST_RECOVERY",
            entity_type="recovery_action",
            entity_id=str(action_id),
            details={
                "incident_code": incident_code,
                "pipeline_id": pipeline_id,
                "action_type": plan.action_type,
                "risk_level": plan.risk_level,
            },
        )
        return action_id

    def approve_recovery(
        self, action_id: int, approved_by: str, user_role: str = "engineer"
    ) -> bool:
        """Authorizes execution of a pending recovery action.

        RBAC Enforcement:
        - 'admin' and 'engineer' roles CAN approve recovery.
        - 'viewer' role is strictly FORBIDDEN from authorizing modifications.
        """
        if user_role not in ["admin", "engineer"]:
            raise PermissionError(
                f"Role '{user_role}' does not have permission to authorize recovery actions. Requires 'engineer' or 'admin'."
            )

        self.repo.approve_recovery_action(
            action_id=action_id, approved_by=approved_by, status="APPROVED"
        )

        self.repo.log_audit_event(
            actor=approved_by,
            action="APPROVE_RECOVERY",
            entity_type="recovery_action",
            entity_id=str(action_id),
            details={"approved_by": approved_by, "role": user_role},
        )
        return True

    def reject_recovery(
        self, action_id: int, rejected_by: str, rejection_reason: str
    ) -> None:
        """Rejects a proposed recovery action."""
        self.repo.approve_recovery_action(
            action_id=action_id, approved_by=rejected_by, status="REJECTED"
        )
        self.repo.log_audit_event(
            actor=rejected_by,
            action="REJECT_RECOVERY",
            entity_type="recovery_action",
            entity_id=str(action_id),
            details={"rejected_by": rejected_by, "reason": rejection_reason},
        )
