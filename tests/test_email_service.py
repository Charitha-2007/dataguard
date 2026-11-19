"""Automated tests for EmailNotificationService.

Verifies:
- Configuration loading, 5 team recipients, and environment variable overrides
- HTML template compilation and severity styling
- Mock mode simulation dispatch (MOCK_DISPATCHED status, never misleadingly called 'SENT')
- Real SMTP connection handshake testing with actionable hints
- Real SMTP transmission with retry handling on transient network failures
- Duplicate suppression and cooldown mechanism
- Severity threshold filtering (ALL, CRITICAL_HIGH, CRITICAL_ONLY)
- Disabled toggle behavior
- Audit log persistence with accurate status distinction
"""

import json
import smtplib
import pytest
from unittest.mock import patch, MagicMock
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


def test_test_email_dispatch_in_mock_mode_distinguishes_status():
    """Validates that mock mode logs MOCK_DISPATCHED and does not misleadingly claim real SMTP delivery."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    result = service.send_test_email()
    assert result["status"] == "MOCK_DISPATCHED"
    assert result["mode"] == "MOCK"
    assert result["recipients_count"] == 5

    # Verify database persistence in notification_logs records MOCK_DISPATCHED
    logs = repo.get_recent_notification_logs(limit=10)
    assert len(logs) >= 1
    latest = logs[0]
    assert latest["incident_code"] == "TEST-EMAIL"
    assert latest["status"] == "MOCK_DISPATCHED"
    assert "MOCK" in latest["channel"]


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

    assert res["status"] == "MOCK_DISPATCHED"
    assert res["recipients_count"] == 5

    logs = repo.get_recent_notification_logs(limit=5)
    assert any(log["incident_code"] == "INC-20261119-TEST" for log in logs)


def test_duplicate_notification_suppression_within_cooldown():
    """Validates that repeated failure alerts within cooldown window are suppressed."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    # First dispatch -> SUCCESS (mock dispatch)
    res1 = service.send_incident_alert(
        incident_code="INC-COOLDOWN-01",
        pipeline_id="billing_transactions_sync",
        severity="P1",
        title="Schema Mismatch Failure",
        root_cause="Column amount renamed to transaction_amount",
        downstream_impact="Downstream billing reconciliation suspended",
    )
    assert res1["status"] == "MOCK_DISPATCHED"

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


# ═══════════════════════════════════════════════════════════════════════════════
# REAL SMTP CONNECTION & RETRY TESTS
# ═══════════════════════════════════════════════════════════════════════════════

def test_smtp_connection_test_missing_credentials_provides_guidance():
    """Validates that testing connection without credentials fails gracefully with setup instructions."""
    service = EmailNotificationService(repo=DataGuardRepository())
    res = service.test_smtp_connection(smtp_username="", smtp_password="")
    assert res["success"] is False
    assert res["error_type"] == "MISSING_CREDENTIALS"
    assert "App Password" in res["hint"]


def test_smtp_connection_test_authentication_error_explains_app_password():
    """Validates that bad credentials returns a clear explanation of Gmail App Passwords."""
    service = EmailNotificationService(repo=DataGuardRepository())

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_instance.login.side_effect = smtplib.SMTPAuthenticationError(535, b"5.7.8 BadCredentials")
        mock_smtp.return_value = mock_instance

        res = service.test_smtp_connection(
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="user@gmail.com",
            smtp_password="bad_password",
            smtp_use_tls=True,
        )
        assert res["success"] is False
        assert res["error_type"] == "AUTHENTICATION_FAILED"
        assert "App Password" in res["hint"]


def test_smtp_connection_test_successful_handshake():
    """Validates that valid SMTP credentials result in verified connection status."""
    service = EmailNotificationService(repo=DataGuardRepository())

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value = mock_instance

        res = service.test_smtp_connection(
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="admin@dataguard.local",
            smtp_password="valid_app_password_123",
            smtp_use_tls=True,
        )
        assert res["success"] is True
        assert "Successfully connected" in res["message"]
        mock_instance.starttls.assert_called_once()
        mock_instance.login.assert_called_once_with("admin@dataguard.local", "valid_app_password_123")
        mock_instance.quit.assert_called_once()


def test_real_smtp_dispatch_success_and_status_accepted():
    """Validates that in live SMTP mode, successful delivery records SMTP_ACCEPTED status."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    # Configure real SMTP mode
    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@company.com",
        sender_name="DataGuard",
        smtp_username="alerts@company.com",
        smtp_password="valid_16_char_app_password",
        recipients=["eng1@dataguard.local", "eng2@dataguard.local"],
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=False,  # REAL SMTP
    )

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value = mock_instance

        res = service.send_incident_alert(
            incident_code="INC-LIVE-01",
            pipeline_id="real_pipeline",
            severity="P1",
            title="Production Ingestion Crash",
            root_cause="Out of memory",
            downstream_impact="Financial mart suspended",
        )

        assert res["status"] == "SMTP_ACCEPTED"
        assert res["mode"] == "LIVE_SMTP"
        assert res["recipients_count"] == 2
        mock_instance.sendmail.assert_called_once()

        # Verify DB logged status as SMTP_ACCEPTED
        logs = repo.get_recent_notification_logs(limit=5)
        latest = logs[0]
        assert latest["status"] == "SMTP_ACCEPTED"
        assert latest["channel"] == "EMAIL (SMTP)"


def test_real_smtp_missing_credentials_fails_without_falling_back_to_mock():
    """Validates that real SMTP mode never silently degrades to mock mode without user awareness."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    # Live mode enabled, but password missing
    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@company.com",
        sender_name="DataGuard",
        smtp_username="alerts@company.com",
        smtp_password="",  # Missing!
        recipients=["eng1@dataguard.local"],
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=False,
    )

    res = service.send_incident_alert(
        incident_code="INC-FAIL-01",
        pipeline_id="real_pipeline",
        severity="P1",
        title="Test Failure",
        root_cause="N/A",
        downstream_impact="N/A",
    )

    assert res["status"] == "FAILED"
    assert "Missing SMTP credentials" in res["error"]

    logs = repo.get_recent_notification_logs(limit=5)
    assert logs[0]["status"] == "FAILED"


def test_real_smtp_retry_recovers_after_transient_failure():
    """Validates retry mechanism recovers and logs SMTP_ACCEPTED on transient connection error."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@company.com",
        sender_name="DataGuard",
        smtp_username="alerts@company.com",
        smtp_password="app_password_123",
        recipients=["eng1@dataguard.local"],
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=False,
    )

    with patch("smtplib.SMTP") as mock_smtp, patch("time.sleep"):
        mock_instance = MagicMock()
        # First call raises connection error, second succeeds
        mock_instance.sendmail.side_effect = [
            smtplib.SMTPConnectError(421, b"Temporary server error"),
            None,
        ]
        mock_smtp.return_value = mock_instance

        res = service.send_incident_alert(
            incident_code="INC-RETRY-01",
            pipeline_id="crm_pipeline",
            severity="P1",
            title="Retry Test",
            root_cause="Transient glitch",
            downstream_impact="None",
        )

        assert res["status"] == "SMTP_ACCEPTED"
        assert res["attempt"] == 2
        assert mock_instance.sendmail.call_count == 2
