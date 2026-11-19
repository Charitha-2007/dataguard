"""Database schemas, dataclasses, and initialization logic for DataGuard.

Defines all relational table structures, foreign key constraints,
data transfer objects (DTOs), and database creation routines.
"""

from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any
import hashlib
import json
import sqlite3
from src.database.connection import get_db, get_connection


# =====================================================================
# SQL SCHEMA DEFINITIONS
# =====================================================================

SCHEMA_SQL = """
-- 1. Users & Roles for RBAC
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'engineer', 'viewer')),
    email TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 2. Pipeline Metadata
CREATE TABLE IF NOT EXISTS pipelines (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    source_type TEXT NOT NULL,
    schedule_cron TEXT DEFAULT '0 * * * *',
    sla_seconds INTEGER NOT NULL DEFAULT 300,
    owner_email TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 3. Pipeline Dependencies (for Downstream Impact DAG)
CREATE TABLE IF NOT EXISTS pipeline_dependencies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    upstream_pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
    downstream_pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
    dependency_type TEXT NOT NULL DEFAULT 'hard',
    UNIQUE(upstream_pipeline_id, downstream_pipeline_id)
);

-- 4. Pipeline Execution Runs & Telemetry
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT UNIQUE NOT NULL,
    pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('RUNNING', 'SUCCESS', 'FAILED', 'RECOVERED')),
    started_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    completed_at TEXT,
    duration_seconds REAL DEFAULT 0.0,
    row_count INTEGER DEFAULT 0,
    error_message TEXT,
    metrics_json TEXT,
    raw_data_path TEXT,
    processed_data_path TEXT
);

-- 5. Incidents & Diagnoses
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_code TEXT UNIQUE NOT NULL,
    run_id TEXT NOT NULL REFERENCES pipeline_runs(run_id) ON DELETE CASCADE,
    pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK(severity IN ('P1', 'P2', 'P3', 'P4')),
    incident_type TEXT NOT NULL,
    root_cause_summary TEXT NOT NULL,
    downstream_impact_summary TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN' CHECK(status IN ('OPEN', 'IN_REVIEW', 'RECOVERED', 'CLOSED')),
    assigned_to TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    resolved_at TEXT
);

-- 6. Approval-Gated Recovery Actions
CREATE TABLE IF NOT EXISTS recovery_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_code TEXT NOT NULL REFERENCES incidents(incident_code) ON DELETE CASCADE,
    pipeline_id TEXT NOT NULL REFERENCES pipelines(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL CHECK(action_type IN ('RETRY', 'DROP_CORRUPTED', 'APPLY_FALLBACK', 'SCHEMA_PATCH')),
    parameters_json TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING_APPROVAL' CHECK(status IN ('PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXECUTING', 'COMPLETED', 'FAILED')),
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    execution_log TEXT,
    is_verified INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 7. Tamper-Evident Hash-Chained Audit Logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    details_json TEXT,
    prev_hash TEXT NOT NULL,
    record_hash TEXT NOT NULL
);

-- 8. Historical Failure Knowledge Base
CREATE TABLE IF NOT EXISTS knowledge_base (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_type TEXT NOT NULL,
    error_pattern TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    resolution_steps TEXT NOT NULL,
    times_used INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- 9. Uploaded Datasets Catalog
CREATE TABLE IF NOT EXISTS uploaded_datasets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    filename TEXT NOT NULL,
    file_type TEXT NOT NULL CHECK(file_type IN ('csv', 'xlsx', 'xls', 'json')),
    file_size_bytes INTEGER NOT NULL,
    row_count INTEGER NOT NULL DEFAULT 0,
    column_count INTEGER NOT NULL DEFAULT 0,
    columns_json TEXT NOT NULL DEFAULT '[]',
    quality_score REAL DEFAULT 0.0,
    missing_count INTEGER DEFAULT 0,
    duplicate_count INTEGER DEFAULT 0,
    file_path TEXT NOT NULL,
    uploaded_by TEXT NOT NULL DEFAULT 'admin',
    uploaded_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    status TEXT NOT NULL DEFAULT 'UPLOADED' CHECK(status IN ('UPLOADED', 'PROCESSED', 'FAILED'))
);

-- 10. Email Notification Settings (Configurable by Administrator)
CREATE TABLE IF NOT EXISTS notification_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    is_enabled INTEGER NOT NULL DEFAULT 1,
    smtp_host TEXT NOT NULL DEFAULT 'smtp.gmail.com',
    smtp_port INTEGER NOT NULL DEFAULT 587,
    smtp_use_tls INTEGER NOT NULL DEFAULT 1,
    smtp_use_ssl INTEGER NOT NULL DEFAULT 0,
    sender_email TEXT NOT NULL DEFAULT 'alerts@dataguard.local',
    sender_name TEXT NOT NULL DEFAULT 'DataGuard Monitoring',
    smtp_username TEXT NOT NULL DEFAULT '',
    smtp_password TEXT NOT NULL DEFAULT '',
    recipients_json TEXT NOT NULL DEFAULT '["lead_architect@dataguard.local", "data_engineer_oncall@dataguard.local", "qa_lead@dataguard.local", "devops_sec@dataguard.local", "product_owner@dataguard.local"]',
    severity_threshold TEXT NOT NULL DEFAULT 'ALL' CHECK(severity_threshold IN ('ALL', 'CRITICAL_HIGH', 'CRITICAL_ONLY')),
    cooldown_minutes INTEGER NOT NULL DEFAULT 30,
    mock_mode INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    updated_by TEXT NOT NULL DEFAULT 'admin'
);

-- 11. Notification Delivery History Logs
CREATE TABLE IF NOT EXISTS notification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    incident_code TEXT,
    pipeline_id TEXT,
    severity TEXT NOT NULL,
    recipients_json TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('SENT', 'SMTP_ACCEPTED', 'MOCK_DISPATCHED', 'FAILED', 'SUPPRESSED_COOLDOWN', 'SUPPRESSED_SEVERITY')),
    error_message TEXT,
    channel TEXT NOT NULL DEFAULT 'EMAIL'
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_runs_pipeline_id ON pipeline_runs(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_runs_status ON pipeline_runs(status);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_pipeline ON incidents(pipeline_id);
CREATE INDEX IF NOT EXISTS idx_audit_entity ON audit_logs(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_datasets_status ON uploaded_datasets(status);
CREATE INDEX IF NOT EXISTS idx_notif_logs_incident ON notification_logs(incident_code);
CREATE INDEX IF NOT EXISTS idx_notif_logs_pipeline ON notification_logs(pipeline_id);
"""


# =====================================================================
# PYTHON DATACLASSES (DATA TRANSFER OBJECTS)
# =====================================================================

@dataclass
class Pipeline:
    id: str
    name: str
    description: str
    source_type: str
    schedule_cron: str = "0 * * * *"
    sla_seconds: int = 300
    owner_email: str = "data-team@dataguard.local"
    is_active: int = 1
    created_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class PipelineRun:
    run_id: str
    pipeline_id: str
    status: str
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    row_count: int = 0
    error_message: Optional[str] = None
    metrics_json: Optional[str] = None
    raw_data_path: Optional[str] = None
    processed_data_path: Optional[str] = None
    id: Optional[int] = None


@dataclass
class Incident:
    incident_code: str
    run_id: str
    pipeline_id: str
    severity: str
    incident_type: str
    root_cause_summary: str
    downstream_impact_summary: Optional[str] = None
    status: str = "OPEN"
    assigned_to: Optional[str] = None
    created_at: Optional[str] = None
    resolved_at: Optional[str] = None
    id: Optional[int] = None


@dataclass
class RecoveryAction:
    incident_code: str
    pipeline_id: str
    action_type: str
    requested_by: str
    parameters_json: Optional[str] = None
    status: str = "PENDING_APPROVAL"
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    execution_log: Optional[str] = None
    is_verified: int = 0
    created_at: Optional[str] = None
    id: Optional[int] = None


@dataclass
class AuditRecord:
    actor: str
    action: str
    entity_type: str
    entity_id: str
    details: Dict[str, Any]
    timestamp: Optional[str] = None
    prev_hash: str = "GENESIS"
    record_hash: str = ""
    id: Optional[int] = None

    def calculate_hash(self, prev_hash: str) -> str:
        """Calculates a SHA-256 tamper-evident hash for this audit record."""
        payload = f"{prev_hash}|{self.timestamp}|{self.actor}|{self.action}|{self.entity_type}|{self.entity_id}|{json.dumps(self.details, sort_keys=True)}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class UploadedDataset:
    id: str
    name: str
    filename: str
    file_type: str
    file_size_bytes: int
    row_count: int
    column_count: int
    columns_json: str
    quality_score: float = 0.0
    missing_count: int = 0
    duplicate_count: int = 0
    file_path: str = ""
    uploaded_by: str = "admin"
    uploaded_at: Optional[str] = None
    status: str = "UPLOADED"


@dataclass
class NotificationSettings:
    is_enabled: bool = True
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    sender_email: str = "alerts@dataguard.local"
    sender_name: str = "DataGuard Monitoring"
    smtp_username: str = ""
    smtp_password: str = ""
    recipients: List[str] = None
    severity_threshold: str = "ALL"
    cooldown_minutes: int = 30
    mock_mode: bool = True
    updated_at: Optional[str] = None
    updated_by: str = "admin"

    def __post_init__(self):
        if self.recipients is None:
            self.recipients = [
                "lead_architect@dataguard.local",
                "data_engineer_oncall@dataguard.local",
                "qa_lead@dataguard.local",
                "devops_sec@dataguard.local",
                "product_owner@dataguard.local",
            ]


@dataclass
class NotificationLog:
    severity: str
    recipients_json: str
    subject: str
    status: str
    incident_code: Optional[str] = None
    pipeline_id: Optional[str] = None
    error_message: Optional[str] = None
    channel: str = "EMAIL"
    timestamp: Optional[str] = None
    id: Optional[int] = None


# =====================================================================
# DATABASE INITIALIZATION ROUTINE
# =====================================================================

def init_db() -> None:
    """Executes schema DDL and seeds initial baseline data (users, pipelines, knowledge base)."""
    with get_db() as conn:
        conn.executescript(SCHEMA_SQL)
        _migrate_notification_logs_if_needed(conn)
        _seed_baseline_data(conn)


def _migrate_notification_logs_if_needed(conn: sqlite3.Connection) -> None:
    """Migrates notification_logs to expand CHECK constraint for real SMTP vs Mock statuses if needed."""
    try:
        # Check if table allows 'SMTP_ACCEPTED'
        conn.execute(
            "INSERT INTO notification_logs (id, timestamp, severity, recipients_json, subject, status) "
            "VALUES (-999, '2000-01-01 00:00:00', 'INFO', '[]', '__migration_probe__', 'SMTP_ACCEPTED');"
        )
        conn.execute("DELETE FROM notification_logs WHERE id = -999;")
    except sqlite3.IntegrityError:
        # CHECK constraint rejected 'SMTP_ACCEPTED'; perform safe table migration
        conn.execute("CREATE TABLE IF NOT EXISTS notification_logs_backup AS SELECT * FROM notification_logs;")
        conn.execute("DROP TABLE notification_logs;")
        conn.execute(
            """CREATE TABLE notification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                incident_code TEXT,
                pipeline_id TEXT,
                severity TEXT NOT NULL,
                recipients_json TEXT NOT NULL,
                subject TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('SENT', 'SMTP_ACCEPTED', 'MOCK_DISPATCHED', 'FAILED', 'SUPPRESSED_COOLDOWN', 'SUPPRESSED_SEVERITY')),
                error_message TEXT,
                channel TEXT NOT NULL DEFAULT 'EMAIL'
            );"""
        )
        conn.execute("INSERT INTO notification_logs SELECT * FROM notification_logs_backup;")
        conn.execute("DROP TABLE notification_logs_backup;")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_logs_incident ON notification_logs(incident_code);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notif_logs_pipeline ON notification_logs(pipeline_id);")


def _seed_baseline_data(conn: sqlite3.Connection) -> None:
    """Seeds initial users, baseline pipelines, and knowledge base if empty."""
    cursor = conn.cursor()

    # 1. Seed Default Users (Admin, Engineer, Viewer)
    cursor.execute("SELECT COUNT(*) FROM users;")
    if cursor.fetchone()[0] == 0:
        # Simple SHA-256 hash for demonstration (e.g. password is 'admin123')
        default_pwd = hashlib.sha256("admin123".encode()).hexdigest()
        users_seed = [
            ("admin", default_pwd, "admin", "admin@dataguard.local"),
            ("engineer_alice", default_pwd, "engineer", "alice@dataguard.local"),
            ("viewer_bob", default_pwd, "viewer", "bob@dataguard.local"),
        ]
        cursor.executemany(
            "INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?);",
            users_seed,
        )

    # 2. Seed Baseline Monitored Pipelines
    cursor.execute("SELECT COUNT(*) FROM pipelines;")
    if cursor.fetchone()[0] == 0:
        pipelines_seed = [
            (
                "crm_customers_etl",
                "CRM Customer Profiles Ingestion",
                "Ingests daily customer signups and profile updates from Salesforce CSV export.",
                "csv",
                "0 2 * * *",
                180,  # 3 minutes SLA
                "crm-ops@company.com",
            ),
            (
                "billing_transactions_sync",
                "Billing & Payment Transactions",
                "Extracts payment transactions, invoices, and chargebacks from Stripe JSON feeds.",
                "json",
                "*/15 * * * *",
                60,   # 1 minute SLA
                "billing-ops@company.com",
            ),
            (
                "analytics_user_events",
                "User Clickstream & Feature Telemetry",
                "Aggregates hourly product usage events for business intelligence dashboards.",
                "json",
                "0 * * * *",
                300,  # 5 minutes SLA
                "bi-team@company.com",
            ),
            (
                "warehouse_finance_mart",
                "Finance Data Mart Aggregator",
                "Aggregates billing and CRM data into executive financial reporting tables.",
                "sql",
                "0 4 * * *",
                450,  # 7.5 minutes SLA
                "finance-data@company.com",
            ),
        ]
        cursor.executemany(
            """INSERT INTO pipelines 
               (id, name, description, source_type, schedule_cron, sla_seconds, owner_email) 
               VALUES (?, ?, ?, ?, ?, ?, ?);""",
            pipelines_seed,
        )

        # 3. Seed Downstream Dependencies (DAG for impact analysis)
        # warehouse_finance_mart depends on crm_customers_etl AND billing_transactions_sync
        dependencies_seed = [
            ("crm_customers_etl", "warehouse_finance_mart", "hard"),
            ("billing_transactions_sync", "warehouse_finance_mart", "hard"),
        ]
        cursor.executemany(
            """INSERT INTO pipeline_dependencies 
               (upstream_pipeline_id, downstream_pipeline_id, dependency_type) 
               VALUES (?, ?, ?);""",
            dependencies_seed,
        )

    # 4. Seed Knowledge Base with Initial Failure Patterns
    cursor.execute("SELECT COUNT(*) FROM knowledge_base;")
    if cursor.fetchone()[0] == 0:
        kb_seed = [
            (
                "SCHEMA_MISMATCH",
                "Missing expected column 'user_id' or renamed to 'customer_id'",
                "Upstream schema alteration without backwards compatibility",
                "SCHEMA_PATCH",
                "1. Apply temporary column alias mapping. 2. Notify upstream data provider to adhere to contract.",
            ),
            (
                "NULL_SPIKE",
                "Sudden surge of null values > 15% in mandatory primary key field",
                "Upstream ingestion worker dropped default value during extraction",
                "DROP_CORRUPTED",
                "1. Quarantine corrupted rows into dead-letter file. 2. Reprocess clean batch. 3. Backfill missing records.",
            ),
            (
                "SLA_BREACH",
                "Pipeline execution exceeded SLA threshold of 180s (took > 400s)",
                "Network timeout or database lock contention during batch insert",
                "RETRY",
                "1. Check database locks. 2. Retry execution with exponential backoff.",
            ),
        ]
        cursor.executemany(
            """INSERT INTO knowledge_base 
               (incident_type, error_pattern, root_cause, recommended_action, resolution_steps) 
               VALUES (?, ?, ?, ?, ?);""",
            kb_seed,
        )

    # 5. Seed Email Notification Settings (5 Team Recipients)
    cursor.execute("SELECT COUNT(*) FROM notification_settings;")
    if cursor.fetchone()[0] == 0:
        default_team = json.dumps([
            "lead_architect@dataguard.local",
            "data_engineer_oncall@dataguard.local",
            "qa_lead@dataguard.local",
            "devops_sec@dataguard.local",
            "product_owner@dataguard.local",
        ])
        cursor.execute(
            """INSERT INTO notification_settings 
               (id, is_enabled, smtp_host, smtp_port, smtp_use_tls, smtp_use_ssl, 
                sender_email, sender_name, smtp_username, smtp_password, 
                recipients_json, severity_threshold, cooldown_minutes, mock_mode, updated_by) 
               VALUES (1, 1, 'smtp.gmail.com', 587, 1, 0, 'alerts@dataguard.local', 
                       'DataGuard Monitoring', '', '', ?, 'ALL', 30, 1, 'admin');""",
            (default_team,),
        )
