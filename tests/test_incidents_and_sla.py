"""Unit tests for Incident Lifecycle Management, SLA Monitoring, and Notifications.

Verifies incident creation, deduplication grouping, lifecycle transitions,
SLA compliance grading, and alert dispatching.
"""

import pytest
from config.settings import DATA_DIR, DATABASE_PATH
from src.database.connection import set_database_path, get_db
from src.database.models import init_db, PipelineRun
from src.database.repository import DataGuardRepository
from src.core.rca_engine import RCADiagnosis
from src.core.impact_analyzer import ImpactReport
from src.core.sla_monitor import SLAMonitor
from src.services.notifier import NotificationDispatcher
from src.services.incident_manager import IncidentManager

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


# =====================================================================
# NOTIFIER & SLA MONITOR TESTS
# =====================================================================

def test_notification_dispatcher_formats_alerts():
    """Verifies that alerts are properly formatted and stored in dispatch history."""
    dispatcher = NotificationDispatcher()
    notif = dispatcher.dispatch_incident_alert(
        incident_code="INC-TEST-101",
        pipeline_id="crm_customers_etl",
        severity="P1",
        title="Schema Contract Violation",
        root_cause="Missing required column 'customer_id'",
        downstream_impact="Blocks warehouse_finance_mart",
        owner_email="crm-ops@company.com",
    )

    assert notif.severity == "P1"
    assert "CRITICAL" in notif.message
    assert "crm_customers_etl" in notif.message
    assert len(dispatcher.sent_notifications) == 1


def test_sla_monitor_evaluates_run_latency():
    """Verifies single run SLA evaluation against latency threshold."""
    monitor = SLAMonitor()
    # SLA is 180s, took 250s
    result = monitor.evaluate_run_sla(sla_target_seconds=180, duration_seconds=250.0)

    assert result["is_breached"] is True
    assert result["overage_seconds"] == 70.0
    assert result["overage_percent"] == 38.9
    assert result["status"] == "BREACHED"


def test_sla_compliance_grading():
    """Verifies historical SLA compliance calculation and health grade."""
    repo = DataGuardRepository()
    # Insert 10 runs for crm_customers_etl (SLA is 180s): 9 compliant, 1 breached
    for i in range(9):
        repo.create_run(
            PipelineRun(
                run_id=f"RUN-SLA-OK-{i}",
                pipeline_id="crm_customers_etl",
                status="SUCCESS",
                started_at="2026-11-18 10:00:00",
                duration_seconds=120.0,
            )
        )
        repo.update_run(
            run_id=f"RUN-SLA-OK-{i}",
            status="SUCCESS",
            completed_at="2026-11-18 10:02:00",
            duration_seconds=120.0,
            row_count=500,
        )

    # 1 breached run
    repo.create_run(
        PipelineRun(
            run_id="RUN-SLA-BREACH-1",
            pipeline_id="crm_customers_etl",
            status="SUCCESS",
            started_at="2026-11-18 10:10:00",
            duration_seconds=300.0,
        )
    )
    repo.update_run(
        run_id="RUN-SLA-BREACH-1",
        status="SUCCESS",
        completed_at="2026-11-18 10:15:00",
        duration_seconds=300.0,
        row_count=500,
    )

    monitor = SLAMonitor(repo=repo)
    report = monitor.get_pipeline_compliance("crm_customers_etl")

    assert report.total_runs_evaluated == 10
    assert report.breached_runs == 1
    assert report.compliance_percentage == 90.0
    assert report.health_grade in ["B", "A"]


# =====================================================================
# INCIDENT MANAGER TESTS
# =====================================================================

def test_incident_creation_and_audit():
    """Verifies that creating an incident saves to DB, logs audit, and sends alert."""
    repo = DataGuardRepository()
    notifier = NotificationDispatcher()
    manager = IncidentManager(repo=repo, notifier=notifier)

    # First record the run in DB so foreign key constraint is satisfied
    repo.create_run(
        PipelineRun(
            run_id="RUN-INC-001",
            pipeline_id="crm_customers_etl",
            status="FAILED",
            started_at="2026-11-18 11:00:00",
        )
    )

    diagnosis = RCADiagnosis(
        incident_type="SCHEMA_MISMATCH",
        severity="P1",
        title="Schema Contract Violation",
        root_cause_summary="Column customer_id missing",
        probable_trigger="Upstream API release",
        recommended_action="SCHEMA_PATCH",
        evidence={"missing": "customer_id"},
    )

    incident = manager.create_incident(
        run_id="RUN-INC-001",
        pipeline_id="crm_customers_etl",
        diagnosis=diagnosis,
    )

    assert incident.incident_code.startswith("INC-")
    assert incident.severity == "P1"
    assert incident.status == "OPEN"

    # Verify notification dispatched
    assert len(notifier.sent_notifications) == 1

    # Verify audit log
    audit_logs = repo.get_recent_audit_logs(limit=5)
    actions = [a["action"] for a in audit_logs]
    assert "CREATE_INCIDENT" in actions


def test_incident_deduplication_and_grouping():
    """Verifies that recurring failures of the same type are grouped into the active incident."""
    repo = DataGuardRepository()
    manager = IncidentManager(repo=repo)

    # Record 2 runs
    repo.create_run(
        PipelineRun(run_id="RUN-GRP-001", pipeline_id="crm_customers_etl", status="FAILED", started_at="2026-11-18 11:00:00")
    )
    repo.create_run(
        PipelineRun(run_id="RUN-GRP-002", pipeline_id="crm_customers_etl", status="FAILED", started_at="2026-11-18 11:15:00")
    )

    diagnosis = RCADiagnosis(
        incident_type="NULL_SPIKE",
        severity="P2",
        title="Null Spike Detected",
        root_cause_summary="40% nulls in email",
        probable_trigger="Extraction bug",
        recommended_action="DROP_CORRUPTED",
        evidence={"null_pct": 40.0},
    )

    inc1 = manager.create_incident(run_id="RUN-GRP-001", pipeline_id="crm_customers_etl", diagnosis=diagnosis)
    inc2 = manager.create_incident(run_id="RUN-GRP-002", pipeline_id="crm_customers_etl", diagnosis=diagnosis)

    # Both should share the same incident code!
    assert inc1.incident_code == inc2.incident_code

    open_incidents = repo.get_all_incidents(status="OPEN")
    # Only 1 incident should exist in DB
    assert len(open_incidents) == 1


def test_incident_lifecycle_transitions():
    """Verifies transitions from OPEN -> IN_REVIEW -> CLOSED."""
    repo = DataGuardRepository()
    manager = IncidentManager(repo=repo)

    repo.create_run(
        PipelineRun(run_id="RUN-LIFE-001", pipeline_id="crm_customers_etl", status="FAILED", started_at="2026-11-18 11:00:00")
    )
    diagnosis = RCADiagnosis(
        incident_type="RUNTIME_EXCEPTION",
        severity="P1",
        title="Crash",
        root_cause_summary="Memory Error",
        probable_trigger="Large batch",
        recommended_action="RETRY",
        evidence={},
    )
    inc = manager.create_incident(run_id="RUN-LIFE-001", pipeline_id="crm_customers_etl", diagnosis=diagnosis)

    # 1. Assign incident -> status becomes IN_REVIEW
    manager.assign_incident(inc.incident_code, assigned_to="alice@company.com", actor="lead_engineer")
    incidents = repo.get_all_incidents(status="IN_REVIEW")
    assert any(i["incident_code"] == inc.incident_code for i in incidents)

    # 2. Close incident -> status becomes CLOSED
    manager.close_incident(inc.incident_code, resolution_notes="Retried with batch size 200.", actor="alice@company.com")
    incidents_closed = repo.get_all_incidents(status="CLOSED")
    assert any(i["incident_code"] == inc.incident_code for i in incidents_closed)
