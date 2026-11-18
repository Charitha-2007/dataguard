"""Unit and integration tests for Approval-Gated Recovery & Automated Verification.

Verifies recommendation generation, RBAC approval enforcement,
quarantine file isolation, recovery execution, and post-recovery quality verification.
"""

import pytest
import os
import pandas as pd
from config.settings import DATA_DIR, DATABASE_PATH, MOCK_DATA_DIR, PROCESSED_DATA_DIR
from src.database.connection import set_database_path, get_db
from src.database.models import init_db, PipelineRun, Incident
from src.database.repository import DataGuardRepository
from src.core.simulator import PipelineSimulator
from src.core.quality_engine import DataQualityEngine
from src.recovery.recommendation import RecoveryRecommendationEngine
from src.recovery.approval_workflow import ApprovalWorkflowManager
from src.recovery.recovery_executor import RecoveryExecutor
from src.recovery.verifier import RecoveryVerifier

TEST_DB_PATH = DATA_DIR / "test_dataguard.db"


@pytest.fixture(autouse=True)
def setup_isolated_test_db():
    """Switches to isolated test database and cleans operational tables."""
    set_database_path(TEST_DB_PATH)
    init_db()

    with get_db() as conn:
        conn.execute("DELETE FROM recovery_actions;")
        conn.execute("DELETE FROM incidents;")
        conn.execute("DELETE FROM pipeline_runs;")
        conn.execute("DELETE FROM audit_logs;")

    yield

    with get_db() as conn:
        conn.execute("DELETE FROM recovery_actions;")
        conn.execute("DELETE FROM incidents;")
        conn.execute("DELETE FROM pipeline_runs;")
        conn.execute("DELETE FROM audit_logs;")

    set_database_path(DATABASE_PATH)


def test_recovery_recommendations_by_incident_type():
    """Verifies that the recommendation engine maps failure types to optimal recovery actions."""
    repo = DataGuardRepository()
    recommender = RecoveryRecommendationEngine(repo=repo)

    plan_null = recommender.generate_plan("NULL_SPIKE", "crm_customers_etl", corrupted_indices=[1, 2, 3])
    assert plan_null.action_type == "DROP_CORRUPTED"
    assert "Quarantine" in plan_null.title

    plan_schema = recommender.generate_plan("SCHEMA_MISMATCH", "crm_customers_etl")
    assert plan_schema.action_type == "SCHEMA_PATCH"

    plan_crash = recommender.generate_plan("RUNTIME_EXCEPTION", "billing_transactions_sync")
    assert plan_crash.action_type == "RETRY"


def test_approval_workflow_rbac_enforcement():
    """Verifies that viewers cannot approve recovery actions, but engineers can."""
    repo = DataGuardRepository()
    workflow = ApprovalWorkflowManager(repo=repo)
    recommender = RecoveryRecommendationEngine(repo=repo)

    # First insert the parent run and incident to satisfy foreign key constraints
    repo.create_run(
        PipelineRun(run_id="RUN-RBAC-001", pipeline_id="crm_customers_etl", status="FAILED", started_at="2026-11-18 10:00:00")
    )
    repo.create_incident(
        Incident(
            incident_code="INC-RBAC-001",
            run_id="RUN-RBAC-001",
            pipeline_id="crm_customers_etl",
            severity="P2",
            incident_type="NULL_SPIKE",
            root_cause_summary="Null values detected",
            status="OPEN",
        )
    )

    plan = recommender.generate_plan("NULL_SPIKE", "crm_customers_etl")
    action_id = workflow.submit_recovery_request("INC-RBAC-001", "crm_customers_etl", plan)

    # 1. Viewer attempt must fail with PermissionError
    with pytest.raises(PermissionError):
        workflow.approve_recovery(action_id, approved_by="viewer_bob", user_role="viewer")

    # 2. Engineer approval must succeed
    assert workflow.approve_recovery(action_id, approved_by="engineer_alice", user_role="engineer") is True

    # Verify status in database
    actions = repo.get_recovery_actions_for_incident("INC-RBAC-001")
    assert actions[0]["status"] == "APPROVED"
    assert actions[0]["approved_by"] == "engineer_alice"


def test_end_to_end_drop_corrupted_recovery_and_verification():
    """Simulates a pipeline with null spike, submits recovery, approves, executes quarantine, and verifies clean data."""
    repo = DataGuardRepository()
    simulator = PipelineSimulator(repo=repo)
    quality_engine = DataQualityEngine()
    recommender = RecoveryRecommendationEngine(repo=repo)
    workflow = ApprovalWorkflowManager(repo=repo)
    executor = RecoveryExecutor(repo=repo, simulator=simulator)
    verifier = RecoveryVerifier(repo=repo, quality_engine=quality_engine)

    # 1. Simulate a run with null spike fault
    run, df = simulator.run_pipeline("crm_customers_etl", fault_type="NULL_SPIKE")

    # 2. Quality evaluation flags nulls
    report = quality_engine.evaluate("crm_customers_etl", df)
    assert report.is_valid is False
    assert len(report.corrupted_indices) > 0

    # 3. Create incident record in DB
    incident = Incident(
        incident_code="INC-RECOV-101",
        run_id=run.run_id,
        pipeline_id="crm_customers_etl",
        severity="P2",
        incident_type="NULL_SPIKE",
        root_cause_summary="Missing emails",
        status="OPEN",
    )
    repo.create_incident(incident)

    # 4. Formulate recovery plan
    plan = recommender.generate_plan(
        incident_type="NULL_SPIKE",
        pipeline_id="crm_customers_etl",
        corrupted_indices=report.corrupted_indices,
        raw_data_path=run.raw_data_path,
    )
    assert plan.action_type == "DROP_CORRUPTED"

    # 5. Submit recovery request
    action_id = workflow.submit_recovery_request("INC-RECOV-101", "crm_customers_etl", plan)

    # 6. Approve recovery
    workflow.approve_recovery(action_id, approved_by="admin", user_role="admin")

    # 7. Execute recovery
    success, log, clean_df = executor.execute(action_id)
    assert success is True
    assert clean_df is not None
    assert len(clean_df) < len(df)  # Corrupted rows were dropped!

    # 8. Post-Recovery Verification
    is_verified, v_report = verifier.verify(action_id, "crm_customers_etl", clean_df, log)
    assert is_verified is True
    assert v_report.is_valid is True
    assert v_report.quality_score == 100.0

    # 9. Verify incident was automatically updated to RECOVERED in DB
    incidents = repo.get_all_incidents()
    target_inc = [i for i in incidents if i["incident_code"] == "INC-RECOV-101"][0]
    assert target_inc["status"] == "RECOVERED"
