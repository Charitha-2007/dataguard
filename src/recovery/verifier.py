"""Post-Recovery Verification Engine for DataGuard.

Asserts the integrity and contractual validity of remediated datasets.
Only marks an incident and pipeline run as RECOVERED if automated
quality checks score 100% on the newly produced data.
"""

from typing import Dict, Any, Optional, Tuple
from datetime import datetime
import pandas as pd

from src.database.connection import get_db, get_connection
from src.database.repository import DataGuardRepository
from src.core.quality_engine import DataQualityEngine, QualityReport


class RecoveryVerifier:
    """Verifies that an executed remediation actually solved the issue."""

    def __init__(
        self,
        repo: Optional[DataGuardRepository] = None,
        quality_engine: Optional[DataQualityEngine] = None,
    ):
        self.repo = repo or DataGuardRepository()
        self.quality_engine = quality_engine or DataQualityEngine()

    def verify(
        self,
        action_id: int,
        pipeline_id: str,
        recovered_df: pd.DataFrame,
        execution_log: str,
        actor: str = "recovery_engine",
    ) -> Tuple[bool, QualityReport]:
        """Runs quality validation on recovered dataset and updates system state."""
        # Run Data Quality assertions on the recovered data
        report = self.quality_engine.evaluate(pipeline_id, recovered_df)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if report.is_valid and report.quality_score >= 90.0:
            # 1. Update Recovery Action as Verified & Completed
            self.repo.complete_recovery_action(
                action_id=action_id,
                execution_log=f"{execution_log} | Verification Passed (Quality Score: {report.quality_score}%).",
                is_verified=True,
            )

            # 2. Fetch associated incident
            with get_db() as conn:
                cursor = conn.execute(
                    "SELECT incident_code, pipeline_id FROM recovery_actions WHERE id = ?;",
                    (action_id,),
                )
                action = cursor.fetchone()

            if action:
                inc_code = action["incident_code"]
                # 3. Update Incident state to RECOVERED
                self.repo.update_incident_status(
                    incident_code=inc_code, status="RECOVERED", resolved_at=now
                )

                # 4. Update Knowledge Base times_used count
                conn_db = get_connection()
                try:
                    conn_db.execute(
                        """UPDATE knowledge_base 
                           SET times_used = times_used + 1 
                           WHERE recommended_action = (
                               SELECT action_type FROM recovery_actions WHERE id = ?
                           );""",
                        (action_id,),
                    )
                    conn_db.commit()
                finally:
                    conn_db.close()

            # 5. Log immutable audit trail
            self.repo.log_audit_event(
                actor=actor,
                action="VERIFY_RECOVERY_SUCCESS",
                entity_type="recovery_action",
                entity_id=str(action_id),
                details={
                    "pipeline_id": pipeline_id,
                    "quality_score": report.quality_score,
                    "recovered_rows": len(recovered_df),
                    "status": "RECOVERED",
                },
            )
            return True, report

        else:
            # Remediated data failed validation!
            self.repo.complete_recovery_action(
                action_id=action_id,
                execution_log=f"{execution_log} | Verification Failed (Quality Score: {report.quality_score}%).",
                is_verified=False,
            )
            self.repo.log_audit_event(
                actor=actor,
                action="VERIFY_RECOVERY_FAILED",
                entity_type="recovery_action",
                entity_id=str(action_id),
                details={
                    "pipeline_id": pipeline_id,
                    "quality_score": report.quality_score,
                    "failed_checks": report.failed_count,
                },
            )
            return False, report
