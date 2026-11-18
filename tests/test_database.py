"""Unit and integration tests for DataGuard Database and Repository.

Verifies schema creation, CRUD operations, foreign key constraints,
and cryptographic audit log integrity verification.
"""

import pytest
import sqlite3
from src.database.models import (
    init_db,
    Pipeline,
    PipelineRun,
    Incident,
    RecoveryAction,
)
from src.database.repository import DataGuardRepository
from src.database.connection import get_db


@pytest.fixture(autouse=True)
def setup_test_db():
    """Initializes the database before each test run."""
    init_db()


def test_init_db_seeds_baseline_data():
    """Verifies that init_db correctly creates tables and seeds default pipelines."""
    repo = DataGuardRepository()
    pipelines = repo.get_all_pipelines()
    
    # We seeded 4 default pipelines
    assert len(pipelines) >= 4
    pipeline_ids = [p["id"] for p in pipelines]
    assert "crm_customers_etl" in pipeline_ids
    assert "billing_transactions_sync" in pipeline_ids
    assert "warehouse_finance_mart" in pipeline_ids


def test_downstream_dependency_mapping():
    """Verifies that the DAG dependency relationships are correctly queried."""
    repo = DataGuardRepository()
    downstream = repo.get_downstream_dependencies("crm_customers_etl")
    
    # warehouse_finance_mart depends on crm_customers_etl
    assert "warehouse_finance_mart" in downstream


def test_pipeline_run_lifecycle():
    """Verifies creating, recording, and updating a pipeline execution run."""
    repo = DataGuardRepository()
    
    # 1. Create a run
    run = PipelineRun(
        run_id="RUN-TEST-001",
        pipeline_id="crm_customers_etl",
        status="RUNNING",
        started_at="2026-11-18 12:00:00",
        raw_data_path="data/raw/test.csv",
    )
    repo.create_run(run)
    
    # 2. Verify run exists
    saved_run = repo.get_run("RUN-TEST-001")
    assert saved_run is not None
    assert saved_run["status"] == "RUNNING"
    
    # 3. Update run with completed metrics
    metrics = {"null_percentage": 0.5, "duplicate_count": 0}
    repo.update_run(
        run_id="RUN-TEST-001",
        status="SUCCESS",
        completed_at="2026-11-18 12:02:15",
        duration_seconds=135.0,
        row_count=1500,
        metrics_json=metrics,
    )
    
    updated_run = repo.get_run("RUN-TEST-001")
    assert updated_run["status"] == "SUCCESS"
    assert updated_run["duration_seconds"] == 135.0
    assert updated_run["row_count"] == 1500
    assert updated_run["metrics"]["null_percentage"] == 0.5


def test_incident_and_recovery_flow():
    """Verifies incident creation, linking, and approval-based recovery."""
    repo = DataGuardRepository()
    
    # Create run first
    repo.create_run(
        PipelineRun(
            run_id="RUN-FAIL-001",
            pipeline_id="billing_transactions_sync",
            status="FAILED",
            started_at="2026-11-18 12:10:00",
        )
    )
    
    # Create incident
    incident = Incident(
        incident_code="INC-TEST-999",
        run_id="RUN-FAIL-001",
        pipeline_id="billing_transactions_sync",
        severity="P1",
        incident_type="NULL_SPIKE",
        root_cause_summary="Critical column transaction_amount contained 35% null values",
        downstream_impact_summary="warehouse_finance_mart blocked",
        assigned_to="alice@dataguard.local",
    )
    repo.create_incident(incident)
    
    open_incidents = repo.get_all_incidents(status="OPEN")
    codes = [i["incident_code"] for i in open_incidents]
    assert "INC-TEST-999" in codes
    
    # Create recovery action
    action = RecoveryAction(
        incident_code="INC-TEST-999",
        pipeline_id="billing_transactions_sync",
        action_type="DROP_CORRUPTED",
        requested_by="ai_recommendation_engine",
    )
    action_id = repo.create_recovery_action(action)
    assert action_id > 0
    
    # Approve recovery action
    repo.approve_recovery_action(action_id, approved_by="admin", status="APPROVED")
    
    # Complete and verify recovery
    repo.complete_recovery_action(
        action_id=action_id,
        execution_log="Dropped 35 corrupt rows, processed remaining 965 clean rows.",
        is_verified=True,
    )
    
    actions = repo.get_recovery_actions_for_incident("INC-TEST-999")
    assert len(actions) == 1
    assert actions[0]["status"] == "COMPLETED"
    assert actions[0]["is_verified"] == 1


def test_audit_log_hash_chain_and_tamper_detection():
    """Verifies that audit log chain calculates valid SHA-256 hashes and detects tampering."""
    repo = DataGuardRepository()
    
    # Log 3 events
    repo.log_audit_event("alice", "TRIGGER_PIPELINE", "pipeline", "crm_customers_etl", {"mode": "manual"})
    repo.log_audit_event("system", "DETECT_FAILURE", "incident", "INC-TEST-999", {"reason": "null_spike"})
    repo.log_audit_event("admin", "APPROVE_RECOVERY", "recovery_action", "1", {"action": "DROP_CORRUPTED"})
    
    # Check integrity
    result = repo.verify_audit_log_integrity()
    assert result["is_valid"] is True
    assert result["total_checked"] >= 3
    
    # Tamper simulation: directly edit a row in SQLite without updating the hash
    with get_db() as conn:
        conn.execute("UPDATE audit_logs SET actor = 'malicious_hacker' WHERE id = 2;")
    
    # Integrity check should immediately detect tampering!
    tamper_result = repo.verify_audit_log_integrity()
    assert tamper_result["is_valid"] is False
    assert "Tampering detected" in tamper_result["reason"] or "Hash chain broken" in tamper_result["reason"]
