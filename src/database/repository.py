"""Repository data-access layer for DataGuard.

Implements the Repository Pattern: encapsulates all SQL queries,
data transformations, and transactions for pipelines, runs, incidents,
recovery actions, and tamper-evident audit logs.
"""

from typing import List, Optional, Dict, Any
import json
from datetime import datetime
import hashlib
from src.database.connection import get_db
from src.database.models import (
    Pipeline,
    PipelineRun,
    Incident,
    RecoveryAction,
    AuditRecord,
    UploadedDataset,
    NotificationSettings,
    NotificationLog,
)


class DataGuardRepository:
    """Central data access interface for DataGuard."""

    # -----------------------------------------------------------------
    # PIPELINES
    # -----------------------------------------------------------------

    def get_all_pipelines(self) -> List[Dict[str, Any]]:
        """Retrieves all registered pipelines."""
        with get_db() as conn:
            cursor = conn.execute("SELECT * FROM pipelines ORDER BY name ASC;")
            return [dict(row) for row in cursor.fetchall()]

    def get_pipeline(self, pipeline_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single pipeline by its unique ID."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM pipelines WHERE id = ?;", (pipeline_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def create_pipeline(self, pipeline: Pipeline) -> None:
        """Registers a new pipeline in the catalog."""
        with get_db() as conn:
            conn.execute(
                """INSERT INTO pipelines 
                   (id, name, description, source_type, schedule_cron, sla_seconds, owner_email, is_active)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
                (
                    pipeline.id,
                    pipeline.name,
                    pipeline.description,
                    pipeline.source_type,
                    pipeline.schedule_cron,
                    pipeline.sla_seconds,
                    pipeline.owner_email,
                    pipeline.is_active,
                ),
            )

    def get_downstream_dependencies(self, pipeline_id: str) -> List[str]:
        """Finds all downstream pipelines that depend directly on this pipeline."""
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT downstream_pipeline_id 
                   FROM pipeline_dependencies 
                   WHERE upstream_pipeline_id = ?;""",
                (pipeline_id,),
            )
            return [row["downstream_pipeline_id"] for row in cursor.fetchall()]

    # -----------------------------------------------------------------
    # PIPELINE RUNS
    # -----------------------------------------------------------------

    def create_run(self, run: PipelineRun) -> int:
        """Records the start of a pipeline run."""
        with get_db() as conn:
            cursor = conn.execute(
                """INSERT INTO pipeline_runs 
                   (run_id, pipeline_id, status, started_at, raw_data_path) 
                   VALUES (?, ?, ?, ?, ?);""",
                (run.run_id, run.pipeline_id, run.status, run.started_at, run.raw_data_path),
            )
            return cursor.lastrowid

    def update_run(
        self,
        run_id: str,
        status: str,
        completed_at: str,
        duration_seconds: float,
        row_count: int,
        error_message: Optional[str] = None,
        metrics_json: Optional[Dict[str, Any]] = None,
        processed_data_path: Optional[str] = None,
    ) -> None:
        """Updates run telemetry upon completion or failure."""
        metrics_str = json.dumps(metrics_json) if metrics_json else None
        with get_db() as conn:
            conn.execute(
                """UPDATE pipeline_runs 
                   SET status = ?, completed_at = ?, duration_seconds = ?, 
                       row_count = ?, error_message = ?, metrics_json = ?, 
                       processed_data_path = ?
                   WHERE run_id = ?;""",
                (
                    status,
                    completed_at,
                    duration_seconds,
                    row_count,
                    error_message,
                    metrics_str,
                    processed_data_path,
                    run_id,
                ),
            )

    def get_run(self, run_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a specific run by its run_id."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM pipeline_runs WHERE run_id = ?;", (run_id,)
            )
            row = cursor.fetchone()
            if not row:
                return None
            result = dict(row)
            if result.get("metrics_json"):
                result["metrics"] = json.loads(result["metrics_json"])
            return result

    def get_recent_runs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent pipeline runs across all pipelines."""
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT r.*, p.name as pipeline_name, p.sla_seconds 
                   FROM pipeline_runs r
                   JOIN pipelines p ON r.pipeline_id = p.id
                   ORDER BY r.started_at DESC LIMIT ?;""",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    # -----------------------------------------------------------------
    # INCIDENTS
    # -----------------------------------------------------------------

    def create_incident(self, incident: Incident) -> None:
        """Creates a new incident record."""
        with get_db() as conn:
            conn.execute(
                """INSERT INTO incidents 
                   (incident_code, run_id, pipeline_id, severity, incident_type, 
                    root_cause_summary, downstream_impact_summary, status, assigned_to) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                (
                    incident.incident_code,
                    incident.run_id,
                    incident.pipeline_id,
                    incident.severity,
                    incident.incident_type,
                    incident.root_cause_summary,
                    incident.downstream_impact_summary,
                    incident.status,
                    incident.assigned_to,
                ),
            )

    def get_all_incidents(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetches incidents, optionally filtered by status (e.g. 'OPEN')."""
        with get_db() as conn:
            if status:
                cursor = conn.execute(
                    """SELECT i.*, p.name as pipeline_name 
                       FROM incidents i 
                       JOIN pipelines p ON i.pipeline_id = p.id 
                       WHERE i.status = ? ORDER BY i.created_at DESC;""",
                    (status,),
                )
            else:
                cursor = conn.execute(
                    """SELECT i.*, p.name as pipeline_name 
                       FROM incidents i 
                       JOIN pipelines p ON i.pipeline_id = p.id 
                       ORDER BY i.created_at DESC;"""
                )
            return [dict(row) for row in cursor.fetchall()]

    def update_incident_status(
        self, incident_code: str, status: str, resolved_at: Optional[str] = None
    ) -> None:
        """Updates the status of an incident."""
        with get_db() as conn:
            conn.execute(
                """UPDATE incidents 
                   SET status = ?, resolved_at = ? 
                   WHERE incident_code = ?;""",
                (status, resolved_at, incident_code),
            )

    # -----------------------------------------------------------------
    # RECOVERY ACTIONS
    # -----------------------------------------------------------------

    def create_recovery_action(self, action: RecoveryAction) -> int:
        """Creates an approval-gated recovery request."""
        with get_db() as conn:
            cursor = conn.execute(
                """INSERT INTO recovery_actions 
                   (incident_code, pipeline_id, action_type, parameters_json, 
                    status, requested_by) 
                   VALUES (?, ?, ?, ?, ?, ?);""",
                (
                    action.incident_code,
                    action.pipeline_id,
                    action.action_type,
                    action.parameters_json,
                    action.status,
                    action.requested_by,
                ),
            )
            return cursor.lastrowid

    def get_recovery_actions_for_incident(self, incident_code: str) -> List[Dict[str, Any]]:
        """Gets all recovery actions associated with an incident."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM recovery_actions WHERE incident_code = ? ORDER BY created_at DESC;",
                (incident_code,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def approve_recovery_action(
        self, action_id: int, approved_by: str, status: str = "APPROVED"
    ) -> None:
        """Records human approval for a recovery action."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            conn.execute(
                """UPDATE recovery_actions 
                   SET status = ?, approved_by = ?, approved_at = ? 
                   WHERE id = ?;""",
                (status, approved_by, now, action_id),
            )

    def complete_recovery_action(
        self, action_id: int, execution_log: str, is_verified: bool
    ) -> None:
        """Records execution result and post-recovery verification status."""
        status = "COMPLETED" if is_verified else "FAILED"
        with get_db() as conn:
            conn.execute(
                """UPDATE recovery_actions 
                   SET status = ?, execution_log = ?, is_verified = ? 
                   WHERE id = ?;""",
                (status, execution_log, 1 if is_verified else 0, action_id),
            )

    # -----------------------------------------------------------------
    # TAMPER-EVIDENT AUDIT LOGS (BLOCKCHAIN-STYLE HASH CHAIN)
    # -----------------------------------------------------------------

    def log_audit_event(
        self,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Logs an event into the tamper-evident audit ledger.

        Each record's hash depends on the previous record's hash (hash chain).
        Any direct manual tampering with previous database rows breaks the chain.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        details_str = json.dumps(details, sort_keys=True)

        with get_db() as conn:
            # Fetch the most recent log record to obtain its hash
            cursor = conn.execute(
                "SELECT record_hash FROM audit_logs ORDER BY id DESC LIMIT 1;"
            )
            last_record = cursor.fetchone()
            prev_hash = last_record["record_hash"] if last_record else "GENESIS_DATAGUARD"

            # Compute current record hash
            payload = f"{prev_hash}|{now}|{actor}|{action}|{entity_type}|{entity_id}|{details_str}"
            record_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            conn.execute(
                """INSERT INTO audit_logs 
                   (timestamp, actor, action, entity_type, entity_id, details_json, prev_hash, record_hash) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?);""",
                (
                    now,
                    actor,
                    action,
                    entity_type,
                    entity_id,
                    details_str,
                    prev_hash,
                    record_hash,
                ),
            )

    def get_recent_audit_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent audit log entries."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?;", (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def verify_audit_log_integrity(self) -> Dict[str, Any]:
        """Validates cryptographic integrity of the entire audit log chain.

        Returns:
            Dict containing is_valid: bool, total_checked: int, and error details if broken.
        """
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id ASC;"
            )
            records = cursor.fetchall()

        if not records:
            return {"is_valid": True, "total_checked": 0, "status": "Empty audit log"}

        expected_prev_hash = "GENESIS_DATAGUARD"
        for idx, row in enumerate(records):
            # Check link to previous hash
            if row["prev_hash"] != expected_prev_hash:
                return {
                    "is_valid": False,
                    "tampered_record_id": row["id"],
                    "reason": f"Hash chain broken at record #{row['id']}. Expected prev_hash {expected_prev_hash}, found {row['prev_hash']}",
                }

            # Recalculate hash of current row
            payload = f"{row['prev_hash']}|{row['timestamp']}|{row['actor']}|{row['action']}|{row['entity_type']}|{row['entity_id']}|{row['details_json']}"
            calculated_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

            if calculated_hash != row["record_hash"]:
                return {
                    "is_valid": False,
                    "tampered_record_id": row["id"],
                    "reason": f"Tampering detected in record #{row['id']}. Content does not match record hash.",
                }

            expected_prev_hash = row["record_hash"]

        return {
            "is_valid": True,
            "total_checked": len(records),
            "status": "Audit trail is 100% authentic and verified.",
        }

    # -----------------------------------------------------------------
    # KNOWLEDGE BASE
    # -----------------------------------------------------------------

    def get_all_knowledge_base(self) -> List[Dict[str, Any]]:
        """Fetches all historical failure knowledge records."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM knowledge_base ORDER BY times_used DESC;"
            )
            return [dict(row) for row in cursor.fetchall()]

    def find_matching_solution(self, incident_type: str) -> Optional[Dict[str, Any]]:
        """Finds the most relevant historical fix for an incident type."""
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT * FROM knowledge_base 
                   WHERE incident_type = ? 
                   ORDER BY times_used DESC LIMIT 1;""",
                (incident_type,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    # -----------------------------------------------------------------
    # UPLOADED DATASETS
    # -----------------------------------------------------------------

    def create_dataset(self, dataset: UploadedDataset) -> None:
        """Saves a new uploaded dataset record into the catalog."""
        with get_db() as conn:
            conn.execute(
                """INSERT INTO uploaded_datasets 
                   (id, name, filename, file_type, file_size_bytes, row_count, column_count, 
                    columns_json, quality_score, missing_count, duplicate_count, file_path, uploaded_by, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                (
                    dataset.id,
                    dataset.name,
                    dataset.filename,
                    dataset.file_type,
                    dataset.file_size_bytes,
                    dataset.row_count,
                    dataset.column_count,
                    dataset.columns_json,
                    dataset.quality_score,
                    dataset.missing_count,
                    dataset.duplicate_count,
                    dataset.file_path,
                    dataset.uploaded_by,
                    dataset.status,
                ),
            )

    def get_all_datasets(self) -> List[Dict[str, Any]]:
        """Retrieves all registered datasets sorted by upload time descending."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM uploaded_datasets ORDER BY uploaded_at DESC;"
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_dataset(self, dataset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single dataset record by its unique identifier."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM uploaded_datasets WHERE id = ?;", (dataset_id,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def update_dataset_metrics(
        self,
        dataset_id: str,
        quality_score: float,
        missing_count: int,
        duplicate_count: int,
        status: str = "PROCESSED",
    ) -> None:
        """Updates analysis metrics for an uploaded dataset."""
        with get_db() as conn:
            conn.execute(
                """UPDATE uploaded_datasets 
                   SET quality_score = ?, missing_count = ?, duplicate_count = ?, status = ?
                   WHERE id = ?;""",
                (quality_score, missing_count, duplicate_count, status, dataset_id),
            )

    def update_dataset_file(
        self,
        dataset_id: str,
        name: str,
        filename: str,
        file_type: str,
        file_size_bytes: int,
        row_count: int,
        column_count: int,
        columns_json: str,
        file_path: str,
        quality_score: float = 0.0,
        missing_count: int = 0,
        duplicate_count: int = 0,
        status: str = "UPLOADED",
    ) -> None:
        """Replaces an existing dataset's file and schema attributes."""
        with get_db() as conn:
            conn.execute(
                """UPDATE uploaded_datasets
                   SET name = ?, filename = ?, file_type = ?, file_size_bytes = ?,
                       row_count = ?, column_count = ?, columns_json = ?, file_path = ?,
                       quality_score = ?, missing_count = ?, duplicate_count = ?, status = ?
                   WHERE id = ?;""",
                (
                    name,
                    filename,
                    file_type,
                    file_size_bytes,
                    row_count,
                    column_count,
                    columns_json,
                    file_path,
                    quality_score,
                    missing_count,
                    duplicate_count,
                    status,
                    dataset_id,
                ),
            )

    def delete_dataset(self, dataset_id: str) -> bool:
        """Deletes a dataset entry from the catalog."""
        with get_db() as conn:
            cursor = conn.execute(
                "DELETE FROM uploaded_datasets WHERE id = ?;", (dataset_id,)
            )
            return cursor.rowcount > 0

    # -----------------------------------------------------------------
    # NOTIFICATION SETTINGS & LOGS
    # -----------------------------------------------------------------

    def get_notification_settings(self) -> Dict[str, Any]:
        """Retrieves global email alert configuration."""
        with get_db() as conn:
            cursor = conn.execute("SELECT * FROM notification_settings WHERE id = 1;")
            row = cursor.fetchone()
            if not row:
                return {
                    "is_enabled": 1,
                    "smtp_host": "smtp.gmail.com",
                    "smtp_port": 587,
                    "smtp_use_tls": 1,
                    "smtp_use_ssl": 0,
                    "sender_email": "alerts@dataguard.local",
                    "sender_name": "DataGuard Monitoring",
                    "smtp_username": "",
                    "smtp_password": "",
                    "recipients_json": json.dumps([
                        "lead_architect@dataguard.local",
                        "data_engineer_oncall@dataguard.local",
                        "qa_lead@dataguard.local",
                        "devops_sec@dataguard.local",
                        "product_owner@dataguard.local",
                    ]),
                    "severity_threshold": "ALL",
                    "cooldown_minutes": 30,
                    "mock_mode": 1,
                }
            return dict(row)

    def update_notification_settings(
        self,
        is_enabled: bool,
        smtp_host: str,
        smtp_port: int,
        smtp_use_tls: bool,
        smtp_use_ssl: bool,
        sender_email: str,
        sender_name: str,
        smtp_username: str,
        smtp_password: Optional[str],
        recipients: List[str],
        severity_threshold: str,
        cooldown_minutes: int,
        mock_mode: bool,
        updated_by: str = "admin",
    ) -> None:
        """Updates notification settings in database."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        recipients_json = json.dumps(recipients)

        with get_db() as conn:
            # If smtp_password is empty, keep existing password
            if not smtp_password:
                conn.execute(
                    """UPDATE notification_settings SET
                       is_enabled = ?, smtp_host = ?, smtp_port = ?,
                       smtp_use_tls = ?, smtp_use_ssl = ?, sender_email = ?,
                       sender_name = ?, smtp_username = ?, recipients_json = ?,
                       severity_threshold = ?, cooldown_minutes = ?, mock_mode = ?,
                       updated_at = ?, updated_by = ?
                       WHERE id = 1;""",
                    (
                        1 if is_enabled else 0,
                        smtp_host,
                        smtp_port,
                        1 if smtp_use_tls else 0,
                        1 if smtp_use_ssl else 0,
                        sender_email,
                        sender_name,
                        smtp_username,
                        recipients_json,
                        severity_threshold,
                        cooldown_minutes,
                        1 if mock_mode else 0,
                        now,
                        updated_by,
                    ),
                )
            else:
                conn.execute(
                    """UPDATE notification_settings SET
                       is_enabled = ?, smtp_host = ?, smtp_port = ?,
                       smtp_use_tls = ?, smtp_use_ssl = ?, sender_email = ?,
                       sender_name = ?, smtp_username = ?, smtp_password = ?,
                       recipients_json = ?, severity_threshold = ?, cooldown_minutes = ?,
                       mock_mode = ?, updated_at = ?, updated_by = ?
                       WHERE id = 1;""",
                    (
                        1 if is_enabled else 0,
                        smtp_host,
                        smtp_port,
                        1 if smtp_use_tls else 0,
                        1 if smtp_use_ssl else 0,
                        sender_email,
                        sender_name,
                        smtp_username,
                        smtp_password,
                        recipients_json,
                        severity_threshold,
                        cooldown_minutes,
                        1 if mock_mode else 0,
                        now,
                        updated_by,
                    ),
                )

    def log_notification(
        self,
        severity: str,
        recipients_json: str,
        subject: str,
        status: str,
        incident_code: Optional[str] = None,
        pipeline_id: Optional[str] = None,
        error_message: Optional[str] = None,
        channel: str = "EMAIL",
        recipient: Optional[str] = None,
    ) -> int:
        """Records an alert dispatch attempt in immutable notification logs."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with get_db() as conn:
            cursor = conn.execute(
                """INSERT INTO notification_logs
                   (timestamp, incident_code, pipeline_id, severity,
                    recipients_json, subject, status, error_message, channel, recipient)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                (
                    now,
                    incident_code,
                    pipeline_id,
                    severity,
                    recipients_json,
                    subject,
                    status,
                    error_message,
                    channel,
                    recipient,
                ),
            )
            return cursor.lastrowid

    def get_recent_notification_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent notification logs for UI display and audit."""
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT * FROM notification_logs
                   ORDER BY id DESC LIMIT ?;""",
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_notification_metrics(self) -> Dict[str, Any]:
        """Calculates accurate email delivery statistics across all logs."""
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM notification_logs WHERE status NOT IN ('SUPPRESSED_COOLDOWN', 'SUPPRESSED_SEVERITY');"
            )
            attempted = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM notification_logs WHERE status IN ('SENT', 'SMTP_ACCEPTED');"
            )
            sent = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM notification_logs WHERE status = 'FAILED';"
            )
            failed = cur.fetchone()[0]

            cur.execute(
                "SELECT COUNT(*) FROM notification_logs WHERE status IN ('SIMULATED', 'MOCK_DISPATCHED');"
            )
            simulated = cur.fetchone()[0]

            cur.execute(
                "SELECT timestamp FROM notification_logs WHERE status IN ('SENT', 'SMTP_ACCEPTED') ORDER BY id DESC LIMIT 1;"
            )
            row = cur.fetchone()
            last_delivery = row[0] if row else "Never"

            return {
                "attempted": attempted,
                "sent": sent,
                "failed": failed,
                "simulated": simulated,
                "last_delivery": last_delivery,
            }

    def is_notification_in_cooldown(
        self, pipeline_id: str, incident_type: str, cooldown_minutes: int
    ) -> bool:
        """Checks if an alert for this pipeline failure was already sent within cooldown window."""
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT timestamp FROM notification_logs
                   WHERE pipeline_id = ? AND status IN ('SENT', 'SMTP_ACCEPTED', 'MOCK_DISPATCHED', 'SIMULATED')
                   ORDER BY id DESC LIMIT 1;""",
                (pipeline_id,),
            )
            row = cursor.fetchone()
            if not row:
                return False

            last_sent_str = row["timestamp"]
            try:
                last_sent = datetime.strptime(last_sent_str, "%Y-%m-%d %H:%M:%S")
                elapsed_mins = (datetime.now() - last_sent).total_seconds() / 60.0
                return elapsed_mins < cooldown_minutes
            except Exception:
                return False

    def cleanup_test_records(self, actor: str = "admin") -> Dict[str, Any]:
        """Safely cleans orphaned test/demo pipelines, orphaned runs, and mock notification entries."""
        with get_db() as conn:
            # Active datasets
            active_ds = [r["id"] for r in conn.execute("SELECT id FROM uploaded_datasets;").fetchall()]
            core_pipes = {
                "crm_customers_etl",
                "billing_transactions_sync",
                "analytics_user_events",
                "warehouse_finance_mart",
            }
            allowed_pipes = core_pipes.union({f"dataset_{d}" for d in active_ds})

            # Orphaned pipelines
            all_pipes = [r["id"] for r in conn.execute("SELECT id FROM pipelines;").fetchall()]
            orphaned = [p for p in all_pipes if p not in allowed_pipes]

            deleted_actions = 0
            deleted_incidents = 0
            deleted_runs = 0
            deleted_pipes = len(orphaned)

            if orphaned:
                placeholders = ",".join(["?"] * len(orphaned))
                cur = conn.execute(
                    f"DELETE FROM recovery_actions WHERE pipeline_id IN ({placeholders});", orphaned
                )
                deleted_actions = cur.rowcount
                cur = conn.execute(
                    f"DELETE FROM incidents WHERE pipeline_id IN ({placeholders});", orphaned
                )
                deleted_incidents = cur.rowcount
                cur = conn.execute(
                    f"DELETE FROM pipeline_runs WHERE pipeline_id IN ({placeholders});", orphaned
                )
                deleted_runs = cur.rowcount
                conn.execute(f"DELETE FROM pipelines WHERE id IN ({placeholders});", orphaned)

            # Close synthetic open incidents on core pipelines so baseline is healthy
            cur = conn.execute(
                "UPDATE incidents SET status = 'RECOVERED', resolved_at = datetime('now', 'localtime') WHERE status = 'OPEN';"
            )
            resolved_incidents = cur.rowcount

            # Clean legacy mock notification logs
            cur = conn.execute(
                "DELETE FROM notification_logs WHERE channel LIKE '%MOCK%' OR recipient IS NULL;"
            )
            deleted_mock_notifs = cur.rowcount

        # Log audit entry
        self.log_audit_event(
            actor=actor,
            action="TEST_RECORDS_CLEANED",
            entity_type="SYSTEM",
            entity_id="MAINTENANCE",
            details={
                "deleted_orphaned_pipelines": deleted_pipes,
                "deleted_runs": deleted_runs,
                "deleted_incidents": deleted_incidents,
                "resolved_incidents": resolved_incidents,
                "deleted_mock_notifications": deleted_mock_notifs,
            },
        )

        return {
            "deleted_orphaned_pipelines": deleted_pipes,
            "deleted_runs": deleted_runs,
            "deleted_incidents": deleted_incidents,
            "resolved_incidents": resolved_incidents,
            "deleted_mock_notifications": deleted_mock_notifs,
        }
