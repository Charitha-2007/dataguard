"""Automated Email Notification Service for DataGuard.

Features:
- Enterprise SMTP delivery (STARTTLS / SSL / Auth) with duplicate suppression & cooldown
- Multipart HTML & Plain-Text responsive email templates
- Configurable team recipients (5 team members)
- Severity-based threshold gating (ALL, CRITICAL_HIGH, CRITICAL_ONLY)
- Graceful sandbox / mock mode for local testing without external internet credentials
- Full delivery auditing into SQLite notification_logs
"""

import os
import json
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
        """Loads configuration from repository with environment variable overrides."""
        cfg = self.repo.get_notification_settings()

        # Allow environment variable overrides for production CI/CD & secrets
        smtp_host = os.environ.get("DATAGUARD_SMTP_HOST", cfg.get("smtp_host", "smtp.gmail.com"))
        smtp_port = int(os.environ.get("DATAGUARD_SMTP_PORT", cfg.get("smtp_port", 587)))
        sender_email = os.environ.get("DATAGUARD_SENDER_EMAIL", cfg.get("sender_email", "alerts@dataguard.local"))
        smtp_user = os.environ.get("DATAGUARD_SMTP_USER", cfg.get("smtp_username", ""))
        smtp_pass = os.environ.get("DATAGUARD_SMTP_PASSWORD", cfg.get("smtp_password", ""))

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
            "mock_mode": bool(cfg.get("mock_mode", 1)),
        }

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

        subject = f"[DataGuard ALERT] [{severity}] Pipeline Failure – {pipeline_id} ({incident_code})"
        
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
        )
        plain_body = (
            f"=== DATAGUARD INCIDENT ALERT ===\n\n"
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

        subject = f"[DataGuard ALERT] [{severity}] SLA Breach – {pipeline_id} (+{overage_percent}%)"
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
        """Dispatches an immediate test email to verify SMTP and team delivery."""
        config = self.get_config()
        recipients = test_recipients or config["recipients"]

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        subject = f"[DataGuard TEST] Operational Email Notification System Verification ({now_str})"
        
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
                            <td style="padding: 8px 0; color: #64748B;">Mode:</td>
                            <td style="padding: 8px 0; color: #00C9FF; font-weight: 600;">{'Sandbox / Simulated Delivery' if config['mock_mode'] else 'Live SMTP Production'}</td>
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
        plain_body = f"DataGuard Test Notification - Delivery verified to {len(recipients)} recipients at {now_str}."

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
        """Handles physical SMTP transport or simulated sandbox delivery with error logging."""
        recipients_json = json.dumps(recipients)

        if not recipients:
            error_msg = "No recipients configured."
            self.repo.log_notification(severity, recipients_json, subject, "FAILED", incident_code, pipeline_id, error_msg)
            return {"status": "FAILED", "error": error_msg}

        # Sandbox / Mock Mode (Default for local environments & tests without real credentials)
        if config["mock_mode"] or not config["smtp_password"]:
            self.repo.log_notification(
                severity=severity,
                recipients_json=recipients_json,
                subject=subject,
                status="SENT",
                incident_code=incident_code,
                pipeline_id=pipeline_id,
                channel="EMAIL (MOCK/SANDBOX)",
            )
            return {
                "status": "SENT",
                "mode": "MOCK",
                "recipients_count": len(recipients),
                "recipients": recipients,
                "subject": subject,
                "message": f"Alert successfully dispatched to {len(recipients)} team member(s) [Sandbox Mode].",
            }

        # Real SMTP Transport
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = f"{config['sender_name']} <{config['sender_email']}>"
            msg["To"] = ", ".join(recipients)

            msg.attach(MIMEText(plain_content, "plain", "utf-8"))
            msg.attach(MIMEText(html_content, "html", "utf-8"))

            if config["smtp_use_ssl"]:
                server = smtplib.SMTP_SSL(config["smtp_host"], config["smtp_port"], timeout=10)
            else:
                server = smtplib.SMTP(config["smtp_host"], config["smtp_port"], timeout=10)

            server.ehlo()
            if config["smtp_use_tls"] and not config["smtp_use_ssl"]:
                server.starttls()
                server.ehlo()

            if config["smtp_username"] and config["smtp_password"]:
                server.login(config["smtp_username"], config["smtp_password"])

            server.sendmail(config["sender_email"], recipients, msg.as_string())
            server.quit()

            self.repo.log_notification(
                severity=severity,
                recipients_json=recipients_json,
                subject=subject,
                status="SENT",
                incident_code=incident_code,
                pipeline_id=pipeline_id,
                channel="EMAIL (SMTP)",
            )
            return {
                "status": "SENT",
                "mode": "LIVE_SMTP",
                "recipients_count": len(recipients),
                "recipients": recipients,
                "subject": subject,
                "message": f"Live email successfully transmitted via {config['smtp_host']} to {len(recipients)} team members.",
            }

        except Exception as e:
            err_str = f"SMTP Transmission Error: {str(e)}"
            self.repo.log_notification(
                severity=severity,
                recipients_json=recipients_json,
                subject=subject,
                status="FAILED",
                incident_code=incident_code,
                pipeline_id=pipeline_id,
                error_message=err_str,
                channel="EMAIL (SMTP)",
            )
            return {
                "status": "FAILED",
                "error": err_str,
                "recipients": recipients,
                "message": f"Failed to deliver email: {str(e)}",
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
                                <p style="margin: 4px 0 0 0; color: #94A3B8; font-size: 13px;">Intelligent Pipeline Reliability & Recovery Guide</p>
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
