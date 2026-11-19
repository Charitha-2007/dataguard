"""Automated tests for EmailNotificationService.

Comprehensive test coverage verifying all 7 specified verification scenarios:
1. Valid Gmail credentials (live SMTP accepted)
2. Invalid password (authentication failure with App Password guidance)
3. Invalid recipient address (handled individually via SMTPRecipientsRefused)
4. SMTP connection failure (timeout/network connection error)
5. Sandbox Mode ON (SIMULATED DELIVERY)
6. Sandbox Mode OFF (Actual SMTP transmission)
7. Multiple team recipients (5 team members receiving individual emails)
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
    assert len(config["recipients"]) == 5
    assert "lead_architect@dataguard.local" in config["recipients"]
    assert "data_engineer_oncall@dataguard.local" in config["recipients"]
    assert "qa_lead@dataguard.local" in config["recipients"]
    assert "devops_sec@dataguard.local" in config["recipients"]
    assert "product_owner@dataguard.local" in config["recipients"]


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 5: SANDBOX MODE ON (SIMULATED DELIVERY)
# ═══════════════════════════════════════════════════════════════════════════════

def test_scenario_5_sandbox_mode_on_records_simulated_delivery():
    """Validates that with Sandbox Mode ON, notifications are recorded as SIMULATED and never SENT."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    result = service.send_test_email()
    assert result["status"] == "SIMULATED"
    assert result["mode"] == "SIMULATED DELIVERY"
    assert result["simulated_count"] == 5
    assert result["sent_count"] == 0

    # Verify each recipient is recorded individually in notification_logs with SIMULATED
    logs = repo.get_recent_notification_logs(limit=10)
    assert len(logs) == 5
    for log in logs:
        assert log["status"] == "SIMULATED"
        assert log["channel"] == "EMAIL (SIMULATED)"
        assert log["recipient"] is not None

    # Check metrics
    metrics = repo.get_notification_metrics()
    assert metrics["simulated"] == 5
    assert metrics["sent"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 6 & 1: SANDBOX MODE OFF & VALID GMAIL CREDENTIALS
# ═══════════════════════════════════════════════════════════════════════════════

def test_scenario_1_and_6_valid_credentials_sandbox_mode_off():
    """Validates that Sandbox Mode OFF uses real SMTP and marks SENT only after SMTP accepts message."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    # Configure Sandbox OFF with valid credentials
    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@dataguard.local",
        sender_name="DataGuard",
        smtp_username="ops@gmail.com",
        smtp_password="valid_16_char_app_password",
        recipients=[
            "lead@dataguard.local",
            "engineer@dataguard.local",
            "qa@dataguard.local",
            "devops@dataguard.local",
            "owner@dataguard.local",
        ],
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=False,  # Sandbox OFF
    )

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value = mock_instance

        result = service.send_test_email()

        assert result["status"] == "SENT"
        assert result["mode"] == "LIVE_SMTP"
        assert result["sent_count"] == 5
        assert result["failed_count"] == 0
        assert mock_instance.sendmail.call_count == 5

        # Verify DB logged each recipient individually as SENT
        logs = repo.get_recent_notification_logs(limit=10)
        assert len(logs) == 5
        for log in logs:
            assert log["status"] == "SENT"
            assert log["channel"] == "EMAIL (SMTP)"

        metrics = repo.get_notification_metrics()
        assert metrics["sent"] == 5
        assert metrics["last_delivery"] != "Never"


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 2: INVALID PASSWORD (AUTHENTICATION FAILURE)
# ═══════════════════════════════════════════════════════════════════════════════

def test_scenario_2_invalid_password_returns_authentication_error():
    """Validates that bad password returns authentication error and records FAILED status."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@dataguard.local",
        sender_name="DataGuard",
        smtp_username="ops@gmail.com",
        smtp_password="wrong_password",
        recipients=["eng@dataguard.local"],
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=False,
    )

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_instance.login.side_effect = smtplib.SMTPAuthenticationError(535, b"5.7.8 BadCredentials")
        mock_smtp.return_value = mock_instance

        res = service.test_smtp_connection(
            smtp_host="smtp.gmail.com",
            smtp_port=587,
            smtp_username="ops@gmail.com",
            smtp_password="wrong_password",
        )
        assert res["success"] is False
        assert res["error_type"] == "AUTHENTICATION_FAILED"
        assert "App Password" in res["hint"]

        # Sending alert also logs FAILED
        alert_res = service.send_test_email()
        assert alert_res["status"] == "FAILED"
        assert alert_res["failed_count"] == 1

        logs = repo.get_recent_notification_logs(limit=5)
        assert logs[0]["status"] == "FAILED"
        assert "Authentication Error" in logs[0]["error_message"]


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 3: INVALID RECIPIENT ADDRESS
# ═══════════════════════════════════════════════════════════════════════════════

def test_scenario_3_invalid_recipient_address_handled_individually():
    """Validates that invalid recipient refused by SMTP is marked FAILED individually while others succeed."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@dataguard.local",
        sender_name="DataGuard",
        smtp_username="ops@gmail.com",
        smtp_password="app_password_123",
        recipients=["valid_user@dataguard.local", "invalid-bad-address@@domain"],
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=False,
    )

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()

        # First call (valid_user) succeeds, second call raises SMTPRecipientsRefused
        def fake_sendmail(sender, recipients, msg_str):
            if "invalid-bad-address" in recipients[0]:
                raise smtplib.SMTPRecipientsRefused({"invalid-bad-address@@domain": (550, b"User unknown")})
            return {}

        mock_instance.sendmail.side_effect = fake_sendmail
        mock_smtp.return_value = mock_instance

        res = service.send_test_email()
        assert res["status"] == "PARTIAL"
        assert res["sent_count"] == 1
        assert res["failed_count"] == 1

        logs = repo.get_recent_notification_logs(limit=5)
        statuses = {l["recipient"]: l["status"] for l in logs}
        assert statuses["valid_user@dataguard.local"] == "SENT"
        assert statuses["invalid-bad-address@@domain"] == "FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 4: SMTP CONNECTION FAILURE
# ═══════════════════════════════════════════════════════════════════════════════

def test_scenario_4_smtp_connection_failure():
    """Validates that network unreachable or connection timeout is caught gracefully."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    with patch("smtplib.SMTP") as mock_smtp:
        mock_smtp.side_effect = smtplib.SMTPConnectError(421, b"Connection refused")

        res = service.test_smtp_connection(
            smtp_host="unreachable.smtp.host",
            smtp_port=587,
            smtp_username="user@gmail.com",
            smtp_password="pwd",
        )
        assert res["success"] is False
        assert res["error_type"] == "CONNECTION_FAILED"


# ═══════════════════════════════════════════════════════════════════════════════
# SCENARIO 7: MULTIPLE TEAM RECIPIENTS (5 TEAM MEMBERS)
# ═══════════════════════════════════════════════════════════════════════════════

def test_scenario_7_multiple_team_recipients_individual_dispatch():
    """Validates that all 5 team members receive separate personalized email dispatches."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    five_team_emails = [
        "lead_architect@dataguard.local",
        "data_engineer_oncall@dataguard.local",
        "qa_lead@dataguard.local",
        "devops_sec@dataguard.local",
        "product_owner@dataguard.local",
    ]

    repo.update_notification_settings(
        is_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_use_tls=True,
        smtp_use_ssl=False,
        sender_email="alerts@dataguard.local",
        sender_name="DataGuard",
        smtp_username="ops@gmail.com",
        smtp_password="app_password_123",
        recipients=five_team_emails,
        severity_threshold="ALL",
        cooldown_minutes=30,
        mock_mode=False,
    )

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value = mock_instance

        res = service.send_incident_alert(
            incident_code="INC-P1-TEAM-ALERT",
            pipeline_id="crm_customers_etl",
            severity="P1",
            title="CRITICAL: Schema Contract Drop",
            root_cause="Column customer_id missing",
            downstream_impact="Financial mart ingestion blocked",
            recommended_action="Quarantine corrupted rows",
        )

        assert res["status"] == "SENT"
        assert res["sent_count"] == 5
        assert len(res["recipient_results"]) == 5

        # Check call arguments: sendmail was called individually for each recipient
        called_recipients = [call[0][1][0] for call in mock_instance.sendmail.call_args_list]
        assert set(called_recipients) == set(five_team_emails)


# ═══════════════════════════════════════════════════════════════════════════════
# ADDITIONAL CORE CONTRACT TESTS
# ═══════════════════════════════════════════════════════════════════════════════

def test_duplicate_notification_suppression_within_cooldown():
    """Validates that repeated failure alerts within cooldown window are suppressed."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

    res1 = service.send_incident_alert(
        incident_code="INC-COOLDOWN-01",
        pipeline_id="billing_transactions_sync",
        severity="P1",
        title="Schema Mismatch Failure",
        root_cause="Column amount renamed",
        downstream_impact="Downstream billing reconciliation suspended",
    )
    assert res1["status"] == "SIMULATED"

    res2 = service.send_incident_alert(
        incident_code="INC-COOLDOWN-01",
        pipeline_id="billing_transactions_sync",
        severity="P1",
        title="Schema Mismatch Failure",
        root_cause="Column amount renamed",
        downstream_impact="Downstream billing reconciliation suspended",
    )
    assert res2["status"] == "SUPPRESSED_COOLDOWN"


def test_severity_threshold_filtering():
    """Validates that alerts below the configured threshold are not dispatched."""
    repo = DataGuardRepository()
    service = EmailNotificationService(repo=repo)

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


def test_send_sample_incident_alert_helper():
    """Validates that the UI button helper generates a complete high-priority incident alert."""
    service = EmailNotificationService(repo=DataGuardRepository())
    res = service.send_sample_incident_alert()
    assert res["status"] in ("SIMULATED", "SENT")
    assert res["recipients_count"] == 5
