"""Automated Email Notification Service for DataGuard.

Features:
- Enterprise SMTP delivery (STARTTLS / SSL / Auth) with duplicate suppression & cooldown
- Dedicated real SMTP connection testing & credential verification
- Retry handling with exponential backoff for transient network errors
- Multi-recipient dispatch (all 5 team members)
- Severity-based threshold gating (ALL, CRITICAL_HIGH, CRITICAL_ONLY)
- Graceful sandbox / mock mode for local testing without external internet credentials
- Clear distinction between MOCK_DISPATCHED, SMTP_ACCEPTED, and FAILED
- Sanitized error reporting (credentials never exposed in logs or UI)
- Full delivery auditing into SQLite notification_logs
"""

import os
import json
import time
import socket
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from typing import Dict, Any, List, Optional

from src.database.repository import DataGuardRepository


class EmailNotificationService:
    """Dispatches automated, high-priority email alerts to the data engineering team."""

    def __init__(self, repo: Optional[DataGuardRepository] = None):
        self.repo = repo or DataGuardRepository()

    def get_config(self) -> Dict[str, Any]:
        """Loads configuration with precedence: Environment Variables > Streamlit Secrets > Database."""
        cfg = self.repo.get_notification_settings()

        # Check Streamlit secrets if running inside Streamlit
        st_smtp = {}
        try:
            import streamlit as st
            if hasattr(st, "secrets"):
                st_smtp = st.secrets.get("smtp", {})
        except Exception:
            pass

        smtp_host = os.environ.get("DATAGUARD_SMTP_HOST", st_smtp.get("host", cfg.get("smtp_host", "smtp.gmail.com")))
        smtp_port = int(os.environ.get("DATAGUARD_SMTP_PORT", st_smtp.get("port", cfg.get("smtp_port", 587))))
        sender_email = os.environ.get(
            "DATAGUARD_SENDER_EMAIL",
            st_smtp.get("sender_email", cfg.get("sender_email", "alerts@dataguard.local")),
        )
        smtp_user = os.environ.get("DATAGUARD_SMTP_USER", st_smtp.get("username", cfg.get("smtp_username", "")))
        smtp_pass = os.environ.get("DATAGUARD_SMTP_PASSWORD", st_smtp.get("password", cfg.get("smtp_password", "")))

        # Mock mode precedence: env var > secrets > database setting
        env_mock = os.environ.get("DATAGUARD_SMTP_MOCK")
        if env_mock is not None:
            mock_mode = env_mock.lower() in ("true", "1", "yes")
        elif "mock_mode" in st_smtp:
            mock_mode = bool(st_smtp["mock_mode"])
        else:
            mock_mode = bool(cfg.get("mock_mode", 1))

        recipients_raw = cfg.get("recipients_json", "[]")
        try:
            recipients = json.loads(recipients_raw) if isinstance(recipients_raw, str) else recipients_raw
        except Exception:
            recipients = [
                "lead_architect@dataguard.local",
                "data_engineer_oncall@dataguard.local",
                "qa_lead@dataguard.local",
                "devops_sec@dataguard.local",
                "product_owner@dataguard.local",
            ]

        return {
            "is_enabled": bool(cfg.get("is_enabled", 1)),
            "smtp_host": smtp_host,
            "smtp_port": smtp_port,
            "smtp_use_tls": bool(cfg.get("smtp_use_tls", 1)),
            "smtp_use_ssl": bool(cfg.get("smtp_use_ssl", 0)),
            "sender_email": sender_email,
            "sender_name": cfg.get("sender_name", "DataGuard Monitoring"),
            "smtp_username": smtp_user,
            "smtp_password": smtp_pass,
            "recipients": recipients,
            "severity_threshold": cfg.get("severity_threshold", "ALL"),
            "cooldown_minutes": int(cfg.get("cooldown_minutes", 30)),
            "mock_mode": mock_mode,
        }

    def _sanitize_error(self, error_str: str, password: Optional[str] = None) -> str:
        """Strips credentials or secrets from error messages before persistence or display."""
        if not error_str:
            return ""
        sanitized = str(error_str)
        if password and len(password) >= 4:
            sanitized = sanitized.replace(password, "●●●●●●●●")
        # Also clean common env password values
        env_pwd = os.environ.get("DATAGUARD_SMTP_PASSWORD")
        if env_pwd and len(env_pwd) >= 4:
            sanitized = sanitized.replace(env_pwd, "●●●●●●●●")
        return sanitized

    def _should_send_for_severity(self, severity: str, threshold: str) -> bool:
        """Determines if the alert meets the configured severity filter."""
        sev_clean = severity.upper()
        if threshold == "ALL":
            return True
        elif threshold == "CRITICAL_HIGH":
            return sev_clean in ["P1", "P2", "CRITICAL", "HIGH"]
        elif threshold == "CRITICAL_ONLY":
            return sev_clean in ["P1", "CRITICAL"]
        return True

    def test_smtp_connection(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_username: Optional[str] = None,
        smtp_password: Optional[str] = None,
        smtp_use_tls: Optional[bool] = None,
        smtp_use_ssl: Optional[bool] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        """Performs a live network handshake and authentication test against the configured SMTP server."""
        cfg = self.get_config()
        host = smtp_host or cfg["smtp_host"]
        port = int(smtp_port or cfg["smtp_port"])
        user = smtp_username if smtp_username is not None else cfg["smtp_username"]
        pwd = smtp_password if smtp_password is not None else cfg["smtp_password"]
        use_tls = smtp_use_tls if smtp_use_tls is not None else cfg["smtp_use_tls"]
        use_ssl = smtp_use_ssl if smtp_use_ssl is not None else cfg["smtp_use_ssl"]

        if not user or not pwd:
            return {
                "success": False,
                "error_type": "MISSING_CREDENTIALS",
                "message": "SMTP Username or App Password is not configured.",
                "hint": (
                    "To send real emails via Gmail (smtp.gmail.com), configure: "
                    "1) SMTP Username (your Gmail address, e.g. you@gmail.com) and "
                    "2) A 16-character Google App Password (generate at https://myaccount.google.com/apppasswords). "
                    "Enter these in the Settings form or export DATAGUARD_SMTP_USER and DATAGUARD_SMTP_PASSWORD."
                ),
            }

        try:
            if use_ssl:
                server = smtplib.SMTP_SSL(host, port, timeout=timeout)
            else:
                server = smtplib.SMTP(host, port, timeout=timeout)

            server.ehlo()
            if use_tls and not use_ssl:
                server.starttls()
                server.ehlo()

            server.login(user, pwd)
            server.quit()

            return {
                "success": True,
                "message": f"Successfully connected and authenticated with {host}:{port} via {'SSL' if use_ssl else 'STARTTLS'}.",
                "host": host,
                "port": port,
                "user": user,
            }

        except smtplib.SMTPAuthenticationError as e:
            err = self._sanitize_error(str(e), pwd)
            return {
                "success": False,
                "error_type": "AUTHENTICATION_FAILED",
                "message": f"SMTP Authentication failed for user '{user}': {err}",
                "hint": (
                    "Gmail requires a 16-character App Password when 2-Step Verification is active. "
                    "Generate an App Password at https://myaccount.google.com/apppasswords and paste it as the SMTP Password. "
                    "Regular Gmail passwords are rejected with '535 5.7.8 BadCredentials'."
                ),
            }
        except (smtplib.SMTPConnectError, ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as e:
            err = self._sanitize_error(str(e), pwd)
            return {
                "success": False,
                "error_type": "CONNECTION_FAILED",
                "message": f"Failed to connect to SMTP server at {host}:{port}: {err}",
                "hint": (
                    f"Check internet connectivity and firewall rules. Ensure outbound TCP connections "
                    f"to port {port} are permitted."
                ),
            }
        except Exception as e:
            err = self._sanitize_error(str(e), pwd)
            return {
                "success": False,
                "error_type": "SMTP_ERROR",
                "message": f"SMTP error during handshake: {err}",
                "hint": "Verify SMTP host, port, TLS/SSL flags, and network routing.",
            }

    def send_incident_alert(
        self,
        incident_code: str,
        pipeline_id: str,
        severity: str,
        title: str,
        root_cause: str,
        downstream_impact: str,
        recommended_action: str = "Triage and authorize recovery action in DataGuard Console.",
        dashboard_url: str = "http://localhost:8501",
    ) -> Dict[str, Any]:
        """Dispatches an incident alert to all team members with cooldown suppression."""
        config = self.get_config()

        if not config["is_enabled"]:
            return {"status": "DISABLED", "message": "Email notifications are disabled in settings."}

        # Check severity threshold
        if not self._should_send_for_severity(severity, config["severity_threshold"]):
            return {
                "status": "SUPPRESSED_SEVERITY",
                "message": f"Alert severity '{severity}' does not meet threshold '{config['severity_threshold']}'.",
            }

        # Check duplicate cooldown
        if self.repo.is_notification_in_cooldown(pipeline_id, title, config["cooldown_minutes"]):
            self.repo.log_notification(
                severity=severity,
                recipients_json=json.dumps(config["recipients"]),
                subject=f"[DataGuard ALERT] {title}",
                status="SUPPRESSED_COOLDOWN",
                incident_code=incident_code,
                pipeline_id=pipeline_id,
                error_message=f"Duplicate alert suppressed within {config['cooldown_minutes']}m cooldown window.",
            )
            return {
                "status": "SUPPRESSED_COOLDOWN",
                "message": f"Alert suppressed: prior notification sent within {config['cooldown_minutes']} min cooldown.",
            }

        mode_tag = " [MOCK]" if config["mock_mode"] else ""
        subject = f"[DataGuard ALERT]{mode_tag} [{severity}] Pipeline Failure – {pipeline_id} ({incident_code})"

        # Build HTML & Plaintext
        html_body = self._build_incident_html(
            incident_code=incident_code,
            pipeline_id=pipeline_id,
            severity=severity,
            title=title,
            root_cause=root_cause,
            downstream_impact=downstream_impact,
            recommended_action=recommended_action,
            dashboard_url=dashboard_url,
            is_mock=config["mock_mode"],
        )
        plain_body = (
            f"=== DATAGUARD INCIDENT ALERT ({'MOCK/SIMULATED' if config['mock_mode'] else 'LIVE SMTP'}) ===\n\n"
            f"Severity: {severity}\n"
            f"Incident Code: {incident_code}\n"
            f"Pipeline: {pipeline_id}\n"
            f"Title: {title}\n"
            f"Root Cause: {root_cause}\n"
            f"Downstream Impact: {downstream_impact}\n"
            f"Suggested Action: {recommended_action}\n"
            f"Dashboard URL: {dashboard_url}\n"
        )

        return self._dispatch_email(
            subject=subject,
            html_content=html_body,
            plain_content=plain_body,
            recipients=config["recipients"],
            incident_code=incident_code,
            pipeline_id=pipeline_id,
            severity=severity,
            config=config,
        )

    def send_sla_breach_alert(
        self,
        pipeline_id: str,
        sla_seconds: int,
        actual_duration_seconds: float,
        overage_percent: float,
        dashboard_url: str = "http://localhost:8501",
    ) -> Dict[str, Any]:
        """Dispatches an alert when a pipeline exceeds its SLA latency budget."""
        config = self.get_config()
        severity = "P1" if overage_percent > 100 else "P2"

        if not config["is_enabled"]:
            return {"status": "DISABLED", "message": "Email notifications are disabled."}

        mode_tag = " [MOCK]" if config["mock_mode"] else ""
        subject = f"[DataGuard ALERT]{mode_tag} [{severity}] SLA Breach – {pipeline_id} (+{overage_percent}%)"
        title = f"Pipeline '{pipeline_id}' latency SLA breached"
        root_cause = f"Execution took {actual_duration_seconds:.2f}s, exceeding budget of {sla_seconds}s by {overage_percent}%."
        impact = "Downstream analytics feeds and business consumers may experience stale data."
        recommended = "Inspect database connection locks, upstream queue delays, or worker resource constraints."

        return self.send_incident_alert(
            incident_code=f"SLA-{pipeline_id}",
            pipeline_id=pipeline_id,
            severity=severity,
            title=title,
            root_cause=root_cause,
            downstream_impact=impact,
            recommended_action=recommended,
            dashboard_url=dashboard_url,
        )

    def send_test_email(self, test_recipients: Optional[List[str]] = None) -> Dict[str, Any]:
        """Dispatches an immediate test email to verify SMTP configuration and team delivery."""
        config = self.get_config()
        recipients = test_recipients or config["recipients"]

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        mode_label = "MOCK / SIMULATED" if config["mock_mode"] else "LIVE SMTP"
        subject = f"[DataGuard TEST] Operational Verification ({mode_label}) – {now_str}"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <body style="margin: 0; padding: 20px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0A0F1E; color: #E2E8F0;">
            <div style="max-width: 650px; margin: 0 auto; background-color: #111827; border: 1px solid rgba(0, 201, 255, 0.3); border-radius: 12px; overflow: hidden; box-shadow: 0 10px 25px rgba(0,0,0,0.5);">
                <div style="background: linear-gradient(90deg, #0A0F1E 0%, #0d1e3d 50%, #0A0F1E 100%); padding: 24px; border-bottom: 1px solid rgba(0, 201, 255, 0.2);">
                    <h1 style="margin: 0; color: #00C9FF; font-size: 22px; font-weight: 700;">🛡️ DataGuard Observability Center</h1>
                    <p style="margin: 6px 0 0 0; color: #94A3B8; font-size: 13px;">Automated Diagnostic & Reliability Notification System</p>
                </div>
                <div style="padding: 24px;">
                    <div style="background-color: rgba(16, 185, 129, 0.1); border-left: 4px solid #10B981; padding: 12px 16px; border-radius: 4px; margin-bottom: 20px;">
                        <strong style="color: #10B981; font-size: 14px;">✅ Operational Delivery Verification Successful</strong>
                        <p style="margin: 4px 0 0 0; font-size: 13px; color: #CBD5E1;">This test email confirms that DataGuard can successfully route real-time operational error alerts to your team members.</p>
                    </div>
                    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px;">
                        <tr>
                            <td style="padding: 8px 0; color: #64748B; width: 140px;">Timestamp:</td>
                            <td style="padding: 8px 0; color: #F1F5F9; font-weight: 600;">{now_str}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #64748B;">SMTP Host:</td>
                            <td style="padding: 8px 0; color: #F1F5F9;">{config['smtp_host']}:{config['smtp_port']}</td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #64748B;">Transport Mode:</td>
                            <td style="padding: 8px 0; color: {'#00C9FF' if config['mock_mode'] else '#10B981'}; font-weight: 600;">
                                {'🧪 Sandbox / Simulated Delivery (Mock)' if config['mock_mode'] else '✉️ Live SMTP Production (TLS 587)'}
                            </td>
                        </tr>
                        <tr>
                            <td style="padding: 8px 0; color: #64748B;">Target Team:</td>
                            <td style="padding: 8px 0; color: #CBD5E1;">{len(recipients)} recipient(s)</td>
                        </tr>
                    </table>
                    <div style="text-align: center; margin-top: 25px;">
                        <a href="http://localhost:8501" style="background: linear-gradient(90deg, #00C9FF 0%, #7C3AED 100%); color: #FFFFFF; text-decoration: none; padding: 10px 24px; border-radius: 8px; font-weight: 600; font-size: 13px; display: inline-block;">Open DataGuard Dashboard</a>
                    </div>
                </div>
                <div style="background-color: #0A0F1E; padding: 14px 24px; text-align: center; border-top: 1px solid rgba(255,255,255,0.06); font-size: 11px; color: #64748B;">
                    DataGuard Intelligent Pipeline Reliability Platform · Automated Alerting Subsystem
                </div>
            </div>
        </body>
        </html>
        """
        plain_body = f"DataGuard Test Notification ({mode_label}) - Delivery verified to {len(recipients)} recipients at {now_str}."

        return self._dispatch_email(
            subject=subject,
            html_content=html_body,
            plain_content=plain_body,
            recipients=recipients,
            incident_code="TEST-EMAIL",
            pipeline_id="system_health_check",
            severity="INFO",
            config=config,
        )

    def _dispatch_email(
        self,
        subject: str,
        html_content: str,
        plain_content: str,
        recipients: List[str],
        incident_code: str,
        pipeline_id: str,
        severity: str,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Dispatches an alert via Real SMTP (with retry) or records a simulated Mock dispatch."""
        recipients_json = json.dumps(recipients)

        if not recipients:
            error_msg = "No recipients configured."
            self.repo.log_notification(severity, recipients_json, subject, "FAILED", incident_code, pipeline_id, error_msg)
            return {"status": "FAILED", "error": error_msg}

        # ── 1. MOCK / SANDBOX MODE ──────────────────────────────────────────
        # When mock_mode is explicitly enabled, we record MOCK_DISPATCHED (never 'SENT')
        if config["mock_mode"]:
            self.repo.log_notification(
                severity=severity,
                recipients_json=recipients_json,
                subject=subject,
                status="MOCK_DISPATCHED",
                incident_code=incident_code,
                pipeline_id=pipeline_id,
                channel="EMAIL (MOCK/SANDBOX)",
            )
            return {
                "status": "MOCK_DISPATCHED",
                "mode": "MOCK",
                "recipients_count": len(recipients),
                "recipients": recipients,
                "subject": subject,
                "message": f"Simulated mock notification generated for {len(recipients)} team member(s) [Sandbox Mode].",
            }

        # ── 2. REAL SMTP PRODUCTION MODE ────────────────────────────────────
        # In live mode, credentials are required. Do NOT silently fall back to mock!
        if not config["smtp_password"] or not config["smtp_username"]:
            err_msg = (
                "Live SMTP delivery failed: Missing SMTP credentials. "
                "Please configure DATAGUARD_SMTP_USER and DATAGUARD_SMTP_PASSWORD, "
                "or enter an App Password in the Settings panel."
            )
            self.repo.log_notification(
                severity=severity,
                recipients_json=recipients_json,
                subject=subject,
                status="FAILED",
                incident_code=incident_code,
                pipeline_id=pipeline_id,
                error_message=err_msg,
                channel="EMAIL (SMTP)",
            )
            return {
                "status": "FAILED",
                "mode": "LIVE_SMTP",
                "error": err_msg,
                "recipients": recipients,
                "message": err_msg,
            }

        # Execute Live SMTP Transmission with Retry Handling (up to 3 attempts)
        max_attempts = 3
        last_error = None

        for attempt in range(1, max_attempts + 1):
            try:
                msg = MIMEMultipart("alternative")
                msg["Subject"] = subject
                msg["From"] = f"{config['sender_name']} <{config['sender_email']}>"
                msg["To"] = ", ".join(recipients)

                msg.attach(MIMEText(plain_content, "plain", "utf-8"))
                msg.attach(MIMEText(html_content, "html", "utf-8"))

                if config["smtp_use_ssl"]:
                    server = smtplib.SMTP_SSL(config["smtp_host"], config["smtp_port"], timeout=12)
                else:
                    server = smtplib.SMTP(config["smtp_host"], config["smtp_port"], timeout=12)

                server.ehlo()
                if config["smtp_use_tls"] and not config["smtp_use_ssl"]:
                    server.starttls()
                    server.ehlo()

                server.login(config["smtp_username"], config["smtp_password"])
                server.sendmail(config["sender_email"], recipients, msg.as_string())
                server.quit()

                # Record successful delivery
                self.repo.log_notification(
                    severity=severity,
                    recipients_json=recipients_json,
                    subject=subject,
                    status="SMTP_ACCEPTED",
                    incident_code=incident_code,
                    pipeline_id=pipeline_id,
                    channel="EMAIL (SMTP)",
                )
                return {
                    "status": "SMTP_ACCEPTED",
                    "mode": "LIVE_SMTP",
                    "recipients_count": len(recipients),
                    "recipients": recipients,
                    "subject": subject,
                    "attempt": attempt,
                    "message": f"SMTP accepted message for delivery to {len(recipients)} team member(s) via {config['smtp_host']}:{config['smtp_port']} (Attempt {attempt}/{max_attempts}).",
                }

            except smtplib.SMTPAuthenticationError as e:
                # Authentication failures will not succeed on retry; exit immediately
                err = self._sanitize_error(str(e), config["smtp_password"])
                last_error = (
                    f"SMTP Authentication Error: {err}. "
                    "For Gmail, use a 16-character Google App Password (https://myaccount.google.com/apppasswords). "
                    "Your regular Google account password is rejected with '535 5.7.8 BadCredentials'."
                )
                break

            except (smtplib.SMTPConnectError, ConnectionRefusedError, socket.timeout, TimeoutError, OSError) as e:
                err = self._sanitize_error(str(e), config["smtp_password"])
                last_error = f"SMTP Connection/Network Error on attempt {attempt}/{max_attempts}: {err}"
                if attempt < max_attempts:
                    time.sleep(1.0 * attempt)

            except Exception as e:
                err = self._sanitize_error(str(e), config["smtp_password"])
                last_error = f"SMTP Transmission Error on attempt {attempt}/{max_attempts}: {err}"
                if attempt < max_attempts:
                    time.sleep(1.0 * attempt)

        # Log failed delivery
        clean_err = self._sanitize_error(str(last_error), config.get("smtp_password"))
        self.repo.log_notification(
            severity=severity,
            recipients_json=recipients_json,
            subject=subject,
            status="FAILED",
            incident_code=incident_code,
            pipeline_id=pipeline_id,
            error_message=clean_err,
            channel="EMAIL (SMTP)",
        )
        return {
            "status": "FAILED",
            "mode": "LIVE_SMTP",
            "error": clean_err,
            "recipients": recipients,
            "message": f"Failed to deliver email after {max_attempts} attempt(s): {clean_err}",
        }

    def _build_incident_html(
        self,
        incident_code: str,
        pipeline_id: str,
        severity: str,
        title: str,
        root_cause: str,
        downstream_impact: str,
        recommended_action: str,
        dashboard_url: str,
        is_mock: bool = False,
    ) -> str:
        """Constructs an enterprise dark-theme HTML email template."""
        sev_colors = {
            "P1": ("#F43F5E", "rgba(244, 63, 94, 0.15)", "CRITICAL (P1)"),
            "P2": ("#F59E0B", "rgba(245, 158, 11, 0.15)", "HIGH (P2)"),
            "P3": ("#00C9FF", "rgba(0, 201, 255, 0.15)", "MEDIUM (P3)"),
            "P4": ("#10B981", "rgba(16, 185, 129, 0.15)", "LOW (P4)"),
        }
        color, bg_color, badge_text = sev_colors.get(severity.upper(), ("#F43F5E", "rgba(244, 63, 94, 0.15)", severity))
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        mode_pill = (
            '<span style="background:rgba(0,201,255,0.15);color:#00C9FF;border:1px solid #00C9FF;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;margin-left:8px;">MOCK SIMULATION</span>'
            if is_mock
            else '<span style="background:rgba(16,185,129,0.15);color:#10B981;border:1px solid #10B981;padding:3px 10px;border-radius:12px;font-size:11px;font-weight:700;margin-left:8px;">LIVE SMTP</span>'
        )

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>DataGuard Pipeline Alert</title>
        </head>
        <body style="margin: 0; padding: 24px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0A0F1E; color: #E2E8F0;">
            <div style="max-width: 680px; margin: 0 auto; background-color: #111827; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; overflow: hidden; box-shadow: 0 12px 30px rgba(0,0,0,0.6);">
                
                <!-- Header -->
                <div style="background: linear-gradient(90deg, #0A0F1E 0%, #0f172a 100%); padding: 24px; border-bottom: 1px solid rgba(0, 201, 255, 0.2);">
                    <table style="width: 100%;">
                        <tr>
                            <td>
                                <h1 style="margin: 0; color: #00C9FF; font-size: 22px; font-weight: 700; letter-spacing: -0.5px;">🛡️ DataGuard Alert Center</h1>
                                <p style="margin: 4px 0 0 0; color: #94A3B8; font-size: 13px;">Intelligent Pipeline Reliability & Recovery Guide {mode_pill}</p>
                            </td>
                            <td style="text-align: right;">
                                <span style="background-color: {bg_color}; color: {color}; border: 1px solid {color}; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700; display: inline-block;">
                                    {badge_text}
                                </span>
                            </td>
                        </tr>
                    </table>
                </div>

                <!-- Alert Headline -->
                <div style="padding: 24px; border-bottom: 1px solid rgba(255, 255, 255, 0.06);">
                    <h2 style="margin: 0 0 8px 0; color: #F1F5F9; font-size: 18px; font-weight: 600;">{title}</h2>
                    <p style="margin: 0; color: #94A3B8; font-size: 13px;">Pipeline ID: <strong style="color: #00C9FF;">{pipeline_id}</strong> &nbsp;·&nbsp; Ticket: <strong style="color: #CBD5E1;">{incident_code}</strong></p>
                </div>

                <!-- Diagnostic Details Table -->
                <div style="padding: 24px;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 24px;">
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);">
                            <td style="padding: 10px 0; color: #64748B; width: 150px; font-weight: 500;">Detected At</td>
                            <td style="padding: 10px 0; color: #F1F5F9; font-weight: 600;">{now_str}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);">
                            <td style="padding: 10px 0; color: #64748B; font-weight: 500;">Root Cause Summary</td>
                            <td style="padding: 10px 0; color: #FCA5A5; line-height: 1.5;">{root_cause}</td>
                        </tr>
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.06);">
                            <td style="padding: 10px 0; color: #64748B; font-weight: 500;">Downstream Blast Radius</td>
                            <td style="padding: 10px 0; color: #FDE047; line-height: 1.5;">{downstream_impact}</td>
                        </tr>
                        <tr>
                            <td style="padding: 10px 0; color: #64748B; font-weight: 500;">Recommended Action</td>
                            <td style="padding: 10px 0; color: #A7F3D0; line-height: 1.5;">{recommended_action}</td>
                        </tr>
                    </table>

                    <!-- CTA Button -->
                    <div style="background-color: #0F172A; border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 20px; text-align: center;">
                        <p style="margin: 0 0 16px 0; font-size: 13px; color: #94A3B8;">Immediate operator authorization or rollback required to restore pipeline SLA.</p>
                        <a href="{dashboard_url}" style="background: linear-gradient(90deg, #00C9FF 0%, #7C3AED 100%); color: #FFFFFF; text-decoration: none; padding: 12px 28px; border-radius: 8px; font-weight: 600; font-size: 14px; display: inline-block; box-shadow: 0 4px 14px rgba(0,201,255,0.3);">
                            Open Incident in DataGuard Console →
                        </a>
                    </div>
                </div>

                <!-- Footer -->
                <div style="background-color: #0A0F1E; padding: 16px 24px; text-align: center; border-top: 1px solid rgba(255,255,255,0.06); font-size: 11px; color: #64748B;">
                    This is an automated operational alert generated by DataGuard. Do not reply directly to this email.<br>
                    Configured recipients: 5 team members · Duplicate suppression active.
                </div>
            </div>
        </body>
        </html>
        """
