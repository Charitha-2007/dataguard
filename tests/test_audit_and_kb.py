"""Unit tests for AuditService, KnowledgeBaseService, and AuthService (RBAC).

Verifies cryptographic audit log queries, tampering detection,
knowledge base search/indexing, and role-based access permissions.
"""

import pytest
from config.settings import DATA_DIR, DATABASE_PATH
from src.database.connection import set_database_path, get_db
from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.services.audit_service import AuditService
from src.services.knowledge_base import KnowledgeBaseService
from src.services.auth import AuthService

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
# AUDIT SERVICE TESTS
# =====================================================================

def test_audit_service_logging_and_filtering():
    """Verifies appending audit records and filtering by actor and action."""
    repo = DataGuardRepository()
    service = AuditService(repo=repo)

    service.log("alice", "LOGIN", "session", "user_1", {"ip": "127.0.0.1"})
    service.log("bob", "VIEW_DASHBOARD", "ui", "page_1", {})
    service.log("alice", "TRIGGER_RUN", "pipeline", "crm_customers_etl", {"mode": "manual"})

    # Filter by actor alice
    alice_logs = service.get_audit_trail(actor="alice")
    assert len(alice_logs) == 2
    actions = [a["action"] for a in alice_logs]
    assert "LOGIN" in actions
    assert "TRIGGER_RUN" in actions

    # Verify integrity
    integrity = service.verify_integrity()
    assert integrity["is_valid"] is True


def test_audit_service_export_dataframe():
    """Verifies that audit trail exports into a clean tabular DataFrame."""
    repo = DataGuardRepository()
    service = AuditService(repo=repo)

    service.log("admin", "SYSTEM_STARTUP", "system", "host_01", {"status": "ok"})
    df = service.export_as_dataframe()

    assert len(df) == 1
    assert "record_hash" in df.columns
    assert df.iloc[0]["actor"] == "admin"


# =====================================================================
# KNOWLEDGE BASE SERVICE TESTS
# =====================================================================

def test_knowledge_base_search_and_recording():
    """Verifies keyword search and registering new failure solutions."""
    repo = DataGuardRepository()
    kb = KnowledgeBaseService(repo=repo)

    # 1. Search seeded solutions
    results = kb.search_solutions("schema")
    assert len(results) >= 1
    assert "SCHEMA_MISMATCH" in [r["incident_type"] for r in results]

    # 2. Record a brand new verified solution
    new_id = kb.record_solution(
        incident_type="CONNECTION_TIMEOUT",
        error_pattern="PostgreSQL connection timed out after 30000ms",
        root_cause="Connection pool exhaustion during peak traffic",
        recommended_action="RETRY",
        resolution_steps="Increase max_connections in postgresql.conf and retry execution.",
    )
    assert new_id > 0

    # 3. Search for the new solution
    matches = kb.search_solutions("exhaustion")
    assert len(matches) == 1
    assert matches[0]["incident_type"] == "CONNECTION_TIMEOUT"

    # 4. Recording identical solution again should increment times_used
    kb.record_solution(
        incident_type="CONNECTION_TIMEOUT",
        error_pattern="PostgreSQL connection timed out after 30000ms",
        root_cause="Connection pool exhaustion during peak traffic",
        recommended_action="RETRY",
        resolution_steps="Increase max_connections in postgresql.conf and retry execution.",
    )
    updated_matches = kb.search_solutions("exhaustion")
    assert updated_matches[0]["times_used"] == 2


# =====================================================================
# AUTH & RBAC SERVICE TESTS
# =====================================================================

def test_auth_service_successful_login():
    """Verifies authentication for seeded accounts."""
    auth = AuthService()

    # Admin
    admin_sess = auth.authenticate("admin", "admin123")
    assert admin_sess is not None
    assert admin_sess.role == "admin"
    assert admin_sess.can_approve_recovery is True
    assert admin_sess.can_manage_settings is True

    # Engineer
    eng_sess = auth.authenticate("engineer_alice", "admin123")
    assert eng_sess is not None
    assert eng_sess.role == "engineer"
    assert eng_sess.can_approve_recovery is True
    assert eng_sess.can_manage_settings is False

    # Viewer
    viewer_sess = auth.authenticate("viewer_bob", "admin123")
    assert viewer_sess is not None
    assert viewer_sess.role == "viewer"
    assert viewer_sess.can_approve_recovery is False  # Read-only!
    assert viewer_sess.can_trigger_pipeline is False


def test_auth_service_invalid_credentials():
    """Verifies that wrong passwords reject authentication."""
    auth = AuthService()
    sess = auth.authenticate("admin", "wrong_password_999")
    assert sess is None
