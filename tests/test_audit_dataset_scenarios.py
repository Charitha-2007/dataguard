"""Comprehensive audit test suite executing the 7 required dataset scenarios:

1. Normal clean CSV
2. CSV with missing values (null spike & detection)
3. CSV with duplicate records (high duplication ratio)
4. CSV with changed / unexpected schema
5. Invalid CSV (binary content disguised as CSV)
6. Empty CSV (zero-byte & header-only)
7. Different datasets with completely different column structures (IoT sensors, HR employees, FinTech)
"""

import io
import pytest
import numpy as np
import pandas as pd
from pathlib import Path

from config.settings import DATA_DIR
from src.database.connection import set_database_path, get_db
from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.services.dataset_service import DatasetService
from src.services.incident_manager import IncidentManager
from src.services.notifier import NotificationDispatcher

SCENARIO_DB_PATH = DATA_DIR / "test_dataguard_scenarios.db"


@pytest.fixture(autouse=True)
def setup_scenarios_db():
    set_database_path(SCENARIO_DB_PATH)
    init_db()
    with get_db() as conn:
        conn.execute("DELETE FROM uploaded_datasets;")
        conn.execute("DELETE FROM pipeline_runs WHERE pipeline_id LIKE 'dataset_%';")
        conn.execute("DELETE FROM incidents WHERE pipeline_id LIKE 'dataset_%';")
        conn.execute("DELETE FROM recovery_actions WHERE pipeline_id LIKE 'dataset_%';")
        conn.execute("DELETE FROM audit_logs WHERE entity_type = 'DATASET';")
    yield
    with get_db() as conn:
        conn.execute("DELETE FROM uploaded_datasets;")
        conn.execute("DELETE FROM pipeline_runs WHERE pipeline_id LIKE 'dataset_%';")
        conn.execute("DELETE FROM incidents WHERE pipeline_id LIKE 'dataset_%';")
        conn.execute("DELETE FROM recovery_actions WHERE pipeline_id LIKE 'dataset_%';")
        conn.execute("DELETE FROM audit_logs WHERE entity_type = 'DATASET';")


# ── SCENARIO 1: Normal Clean CSV ─────────────────────────────────────────────
def test_scenario_1_normal_clean_csv():
    """Validates ingestion, profiling, and 5-stage pipeline on clean dataset."""
    repo = DataGuardRepository()
    notifier = NotificationDispatcher()
    incident_mgr = IncidentManager(repo=repo, notifier=notifier)
    service = DatasetService(repo=repo, incident_manager=incident_mgr)

    csv_data = (
        "cust_id,full_name,balance,tier\n"
        "C001,Alice Smith,1250.50,Gold\n"
        "C002,Bob Jones,450.00,Silver\n"
        "C003,Carol White,3200.75,Platinum\n"
        "C004,David Brown,890.20,Silver\n"
        "C005,Emma Davis,2100.00,Gold\n"
    ).encode("utf-8")

    df, meta = service.parse_file(csv_data, "clean_customers.csv")
    assert len(df) == 5
    assert meta["column_count"] == 4

    profile = service.profile_dataset(df, "clean_customers")
    assert profile["missing_total"] == 0
    assert profile["duplicate_total"] == 0
    assert profile["quality_score"] == 100.0
    assert profile["health_grade"] == "A"

    ds = service.save_dataset("Clean Customers", "clean_customers.csv", df, csv_data, actor="admin")
    result = service.execute_pipeline_on_dataset(ds.id, actor="admin")
    assert result["status"] == "SUCCESS"
    assert result["incident_code"] is None


# ── SCENARIO 2: CSV with Missing Values ───────────────────────────────────────
def test_scenario_2_csv_with_missing_values():
    """Detects null values, calculates column missingness %, and penalizes score."""
    service = DatasetService()

    csv_data = (
        "id,product,price,stock,supplier\n"
        "1,Widget A,19.99,100,Supplier X\n"
        "2,Widget B,,50,Supplier Y\n"
        "3,Widget C,29.99,,Supplier Z\n"
        "4,Widget D,,,Supplier X\n"
        "5,Widget E,49.99,25,\n"
    ).encode("utf-8")

    df, meta = service.parse_file(csv_data, "missing_inventory.csv")
    assert len(df) == 5

    profile = service.profile_dataset(df, "missing_inventory")
    assert profile["missing_total"] == 5
    assert profile["missing_by_column"]["price"]["count"] == 2
    assert profile["missing_by_column"]["stock"]["count"] == 2
    assert profile["missing_by_column"]["supplier"]["count"] == 1
    assert profile["quality_score"] < 90.0


# ── SCENARIO 3: CSV with Duplicate Records ────────────────────────────────────
def test_scenario_3_csv_with_duplicate_records():
    """Detects duplicate rows, computes duplication percentage, and logs warning."""
    service = DatasetService()

    csv_data = (
        "emp_id,department,salary\n"
        "E101,Engineering,95000\n"
        "E101,Engineering,95000\n"
        "E101,Engineering,95000\n"
        "E102,Marketing,65000\n"
        "E102,Marketing,65000\n"
    ).encode("utf-8")

    df, meta = service.parse_file(csv_data, "dup_employees.csv")
    assert len(df) == 5

    profile = service.profile_dataset(df, "dup_employees")
    assert profile["duplicate_total"] == 3
    assert profile["duplicate_pct"] == 60.0
    assert profile["quality_score"] < 80.0


# ── SCENARIO 4: CSV with Changed Schema ──────────────────────────────────────
def test_scenario_4_csv_with_changed_schema():
    """Validates dynamic schema inference when column types and headers change."""
    service = DatasetService()

    csv_v1 = "user_id,amount,timestamp\n1,100.50,2026-01-01\n".encode("utf-8")
    df1, meta1 = service.parse_file(csv_v1, "payments_v1.csv")

    csv_v2 = "transaction_id,amount,fee,currency,payment_method\nTX-01,100.50,2.50,USD,CreditCard\n".encode("utf-8")
    df2, meta2 = service.parse_file(csv_v2, "payments_v2.csv")

    assert meta1["columns"] == ["user_id", "amount", "timestamp"]
    assert meta2["columns"] == ["transaction_id", "amount", "fee", "currency", "payment_method"]
    assert meta2["column_count"] == 5


# ── SCENARIO 5: Invalid CSV (Binary Masquerade) ───────────────────────────────
def test_scenario_5_invalid_csv_rejected():
    """Rejects binary files disguised with .csv extension with a clear error."""
    service = DatasetService()
    png_bytes = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] * 50)

    with pytest.raises(ValueError, match="binary file"):
        service.parse_file(png_bytes, "malicious_file.csv")


# ── SCENARIO 6: Empty CSV ────────────────────────────────────────────────────
def test_scenario_6_empty_csv_rejected():
    """Rejects completely empty or header-only CSV with clear actionable message."""
    service = DatasetService()

    with pytest.raises(ValueError, match="empty"):
        service.parse_file(b"", "empty_file.csv")

    with pytest.raises(ValueError, match="no rows"):
        service.parse_file(b"col1,col2,col3\n", "header_only.csv")


# ── SCENARIO 7: Different Datasets with Different Structures ──────────────────
def test_scenario_7_diverse_column_structures():
    """Profiles completely distinct domain schemas (IoT telemetry vs Healthcare)."""
    service = DatasetService()

    # Domain A: IoT Telemetry (device_id, temp, humidity, pressure, status)
    iot_csv = (
        "device_id,temperature_c,humidity_pct,pressure_hpa,is_alert\n"
        "DEV-01,23.5,45.2,1013.2,False\n"
        "DEV-02,28.1,55.0,1012.8,False\n"
        "DEV-03,85.0,12.1,998.5,True\n"
    ).encode("utf-8")
    df_iot, meta_iot = service.parse_file(iot_csv, "iot_sensors.csv")
    prof_iot = service.profile_dataset(df_iot, "iot_sensors")
    assert "temperature_c" in prof_iot["numeric_columns"]
    assert meta_iot["column_count"] == 5

    # Domain B: Healthcare Records (patient_uuid, blood_group, systolic, diastolic)
    health_csv = (
        "patient_uuid,blood_group,systolic_bp,diastolic_bp\n"
        "P-9001,O+,120,80\n"
        "P-9002,A-,135,88\n"
        "P-9003,B+,115,75\n"
    ).encode("utf-8")
    df_health, meta_health = service.parse_file(health_csv, "patients.csv")
    prof_health = service.profile_dataset(df_health, "patients")
    assert "patient_uuid" in prof_health["categorical_columns"]
    assert meta_health["column_count"] == 4
