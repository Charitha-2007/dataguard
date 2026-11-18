"""Unit tests for PipelineSimulator and Fault Injection Engine.

Tests data generation, fault injection mechanics (Schema Mismatch, Null Spikes,
Value Anomalies), file serialization, and telemetry DB logging.
"""

import pytest
import os
import pandas as pd
from config.settings import DATA_DIR, DATABASE_PATH
from src.database.connection import set_database_path, get_db
from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.core.simulator import PipelineSimulator

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


def test_clean_crm_data_generation():
    """Verifies that clean CRM data follows expected schema and constraints."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=200, fault_type=None)

    assert len(df) == 200
    expected_cols = {"customer_id", "name", "email", "signup_date", "country", "account_balance"}
    assert set(df.columns) == expected_cols
    assert df["email"].isna().sum() == 0
    assert (df["account_balance"] >= 0).all()


def test_schema_mismatch_fault_injection():
    """Verifies that SCHEMA_MISMATCH drops expected columns and introduces unexpected ones."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=100, fault_type="SCHEMA_MISMATCH")

    assert "customer_id" not in df.columns
    assert "legacy_balance_v1" in df.columns


def test_null_spike_fault_injection():
    """Verifies that NULL_SPIKE injects significant missing values into critical columns."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=300, fault_type="NULL_SPIKE")

    null_count = df["email"].isna().sum()
    null_pct = (null_count / len(df)) * 100
    assert null_pct > 20.0  # Should be around 35%


def test_anomaly_values_fault_injection():
    """Verifies that ANOMALY_VALUES injects extreme corrupt values."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=200, fault_type="ANOMALY_VALUES")

    # Extreme negative balances should be present
    corrupt_balances = df[df["account_balance"] < 0]
    assert len(corrupt_balances) > 0
    assert -99999.0 in corrupt_balances["account_balance"].values


def test_run_pipeline_persists_run_and_creates_file():
    """Verifies end-to-end execution of a simulated pipeline run."""
    repo = DataGuardRepository()
    simulator = PipelineSimulator(repo=repo)

    run, df = simulator.run_pipeline("crm_customers_etl", fault_type=None)

    assert run.run_id.startswith("RUN-")
    assert run.pipeline_id == "crm_customers_etl"
    assert run.row_count == 400
    assert os.path.exists(run.raw_data_path)

    # Verify run exists in SQLite
    db_run = repo.get_run(run.run_id)
    assert db_run is not None
    assert db_run["status"] == "RUNNING"

    # Verify audit event was logged
    audit_logs = repo.get_recent_audit_logs(limit=5)
    actions = [a["action"] for a in audit_logs]
    assert "TRIGGER_RUN" in actions

    # Clean up created file
    if os.path.exists(run.raw_data_path):
        os.remove(run.raw_data_path)
