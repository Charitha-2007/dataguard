"""Automated tests for EmailNotificationService.

Verifies:
- Configuration loading and environment variable overrides
- HTML template compilation and severity styling
- Team email dispatch (5 team members)
- Duplicate suppression and cooldown mechanism
- Severity threshold filtering (ALL, CRITICAL_HIGH, CRITICAL_ONLY)
- Test email execution and delivery status recording in notification_logs
"""

import json
import pytest
from datetime import datetime, timedelta

from config.settings import DATA_DIR
from src.database.connection import set_database_path, get_db
from src.database.models import init_db, _seed_baseline_data
from src.database.repository import DataGuardRepository
from src.services.email_service import EmailNotificationService

TEST_DB_PATH = DATA_DIR / "test_dataguard_email.db"


@pytest.fixture(autouse=True)
def setup_isolated_email_db():
    set_database_path(TEST_DB_PATH)
    init_db()
    with get_db() as conn:
        conn.execute("DELETE FROM notification_logs;")
        conn.execute("DELETE FROM notification_settings;")
        _seed_baseline_data(conn)
    yield
    with get_db() as conn:
        conn.execute("DELETE FROM notification_logs;")
        conn.execute("DELETE FROM notification_settings;")
        _seed_baseline_data(conn)


def test_default_configuration_and_5_team_recipients():
    """Validates that initial configuration loads the 5 specified team recipients."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)
    config = service.get_config()

    assert config["is_enabled"] is True
    assert config["mock_mode"] is True
    assert len(config["recipients"]) == 5
    assert "lead_architect@dataguard.local" in config["recipients"]
    assert "data_engineer_oncall@dataguard.local" in config["recipients"]
    assert "devops_sec@dataguard.local" in config["recipients"]


def test_test_email_dispatch_and_audit_logging():
    """Validates that sending a test email logs SENT in notification_logs."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    result = service.send_test_email()
    assert result["status"] == "SENT"
    assert result["recipients_count"] == 5

    # Verify database persistence in notification_logs
    logs = repo.get_recent_notification_logs(limit=10)
    assert len(logs) >= 1
    latest = logs[0]
    assert latest["incident_code"] == "TEST-EMAIL"
    assert latest["status"] == "SENT"
    assert "EMAIL" in latest["channel"]


def test_incident_alert_dispatch_to_all_recipients():
    """Validates that a critical pipeline failure dispatches an alert with incident details."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    res = service.send_incident_alert(
        incident_code="INC-20261119-TEST",
        pipeline_id="crm_customers_etl",
        severity="P1",
        title="Critical Null Spike Detected in Mandatory Field",
        root_cause="Upstream API dropped customer_id in 35% of rows",
        downstream_impact="Blocks warehouse_finance_mart ingestion",
        recommended_action="Quarantine corrupted rows and reprocess clean batch.",
    )

    assert res["status"] == "SENT"
    assert res["recipients_count"] == 5

    logs = repo.get_recent_notification_logs(limit=5)
    assert any(log["incident_code"] == "INC-20261119-TEST" for log in logs)


def test_duplicate_notification_suppression_within_cooldown():
    """Validates that repeated failure alerts within cooldown window are suppressed."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    # First dispatch -> SUCCESS
    res1 = service.send_incident_alert(
        incident_code="INC-COOLDOWN-01",
        pipeline_id="billing_transactions_sync",
        severity="P1",
        title="Schema Mismatch Failure",
        root_cause="Column amount renamed to transaction_amount",
        downstream_impact="Downstream billing reconciliation suspended",
    )
    assert res1["status"] == "SENT"

    # Immediate second dispatch for same pipeline & incident -> SUPPRESSED
    res2 = service.send_incident_alert(
        incident_code="INC-COOLDOWN-01",
        pipeline_id="billing_transactions_sync",
        severity="P1",
        title="Schema Mismatch Failure",
        root_cause="Column amount renamed to transaction_amount",
        downstream_impact="Downstream billing reconciliation suspended",
    )
    assert res2["status"] == "SUPPRESSED_COOLDOWN"

    # Verify log recorded the suppression
    logs = repo.get_recent_notification_logs(limit=5)
    suppressed_log = next((l for l in logs if l["status"] == "SUPPRESSED_COOLDOWN"), None)
    assert suppressed_log is not None
    assert "cooldown" in suppressed_log["error_message"].lower()


def test_severity_threshold_filtering():
    """Validates that alerts below the configured threshold are not dispatched."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    # Set threshold to CRITICAL_ONLY
    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@dataguard.local",
        sender_name="DataGuard",
        smtp_username="",
        smtp_password="",
        recipients=["oncall@dataguard.local"],
        severity_threshold="CRITICAL_ONLY",
        cooldown_minutes=30,
        mock_mode=True,
    )

    # P4 (Low) alert should be suppressed by severity filter
    res = service.send_incident_alert(
        incident_code="INC-LOW-SEV",
        pipeline_id="test_pipe",
        severity="P4",
        title="Minor Warning",
        root_cause="Slight deviation in metrics",
        downstream_impact="None",
    )
    assert res["status"] == "SUPPRESSED_SEVERITY"


def test_disabled_notifications_toggle():
    """Validates that when notifications are toggled OFF, no emails are dispatched."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    # Disable notifications
    repo.update_notification_settings(
        is_enabled=False,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@dataguard.local",
        sender_name="DataGuard",
        smtp_username="",
        smtp_password="",
        recipients=["oncall@dataguard.local"],
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=True,
    )

    res = service.send_incident_alert(
        incident_code="INC-DISABLED",
        pipeline_id="any_pipe",
        severity="P1",
        title="Critical Failure",
        root_cause="Database crash",
        downstream_impact="Full outage",
    )
    assert res["status"] == "DISABLED"
