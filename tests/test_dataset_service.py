"""Unit and integration tests for DatasetService.

Verifies:
- File format parsing (.csv, .xlsx, .json) and error validation
- Dynamic profiling: missing values, duplicates, statistical outliers, data health score
- Dataset catalog lifecycle: save, get, replace, and safe deletion
- 5-stage observable pipeline execution with incident gating
"""

import io
import json
import pytest
import pandas as pd
from pathlib import Path
from config.settings import DATA_DIR
from src.database.connection import set_database_path, get_db
from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.services.dataset_service import DatasetService
from src.services.incident_manager import IncidentManager
from src.services.notifier import NotificationDispatcher

TEST_DB_PATH = DATA_DIR / "test_dataguard.db"


@pytest.fixture(autouse=True)
def setup_isolated_test_db():
    set_database_path(TEST_DB_PATH)
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


def test_csv_parsing_and_profiling():
    service = DatasetService()
    csv_content = b"id,name,amount,status\n1,Alice,100.5,active\n2,Bob,250.0,active\n3,Charlie,,pending\n4,David,500.0,active\n"
    df, meta = service.parse_file(csv_content, "customers.csv")
    assert len(df) == 4
    assert meta["column_count"] == 4
    assert "amount" in df.columns

    profile = service.profile_dataset(df, "customers")
    assert profile["total_rows"] == 4
    assert profile["missing_total"] == 1
    assert profile["missing_by_column"]["amount"]["count"] == 1
    assert profile["duplicate_total"] == 0
    assert profile["quality_score"] > 80.0


def test_json_parsing_and_profiling():
    service = DatasetService()
    json_data = [
        {"tx_id": "T1", "amount": 99.0, "currency": "USD"},
        {"tx_id": "T2", "amount": 150.0, "currency": "USD"},
        {"tx_id": "T3", "amount": 200.0, "currency": "EUR"},
    ]
    raw_bytes = json.dumps(json_data).encode("utf-8")
    df, meta = service.parse_file(raw_bytes, "transactions.json")
    assert len(df) == 3
    assert "currency" in df.columns

    profile = service.profile_dataset(df, "transactions")
    assert profile["total_rows"] == 3
    assert profile["missing_total"] == 0
    assert profile["quality_score"] >= 95.0


def test_excel_parsing():
    service = DatasetService()
    df_sample = pd.DataFrame({
        "order_id": [101, 102, 103],
        "customer": ["Alice", "Bob", "Charlie"],
        "total": [45.5, 80.0, 120.25],
    })
    buffer = io.BytesIO()
    df_sample.to_excel(buffer, index=False, engine="openpyxl")
    buffer.seek(0)
    raw_bytes = buffer.read()

    df, meta = service.parse_file(raw_bytes, "orders.xlsx")
    assert len(df) == 3
    assert meta["file_type"] == "xlsx"
    assert "customer" in df.columns


def test_invalid_and_empty_file_validation():
    service = DatasetService()
    with pytest.raises(ValueError, match="empty"):
        service.parse_file(b"", "empty.csv")

    with pytest.raises(ValueError, match="Unsupported file format"):
        service.parse_file(b"some content", "data.parquet")


def test_dataset_crud_and_lifecycle():
    repo = DataGuardRepository()
    service = DatasetService(repo=repo)

    csv_data = b"user_id,email,score\n1,u1@test.com,90\n2,u2@test.com,85\n"
    df, _ = service.parse_file(csv_data, "users.csv")

    # 1. Save
    dataset = service.save_dataset(
        name="Users Batch",
        filename="users.csv",
        df=df,
        raw_bytes=csv_data,
        actor="engineer_alice",
    )
    assert dataset.id.startswith("DS-")
    assert dataset.row_count == 2

    # 2. Retrieve
    retrieved = repo.get_dataset(dataset.id)
    assert retrieved is not None
    assert retrieved["name"] == "Users Batch"

    # 3. Replace
    csv_replaced = b"user_id,email,score\n1,u1@test.com,90\n2,u2@test.com,85\n3,u3@test.com,95\n"
    df_rep, _ = service.parse_file(csv_replaced, "users_v2.csv")
    updated = service.replace_dataset(
        dataset_id=dataset.id,
        new_name="Users Batch V2",
        new_filename="users_v2.csv",
        df=df_rep,
        raw_bytes=csv_replaced,
        actor="admin",
    )
    assert updated.row_count == 3
    assert updated.name == "Users Batch V2"

    # 4. Delete
    deleted = service.delete_dataset(dataset.id, actor="admin")
    assert deleted is True
    assert repo.get_dataset(dataset.id) is None


def test_pipeline_execution_on_clean_dataset():
    repo = DataGuardRepository()
    notifier = NotificationDispatcher()
    incident_mgr = IncidentManager(repo=repo, notifier=notifier)
    service = DatasetService(repo=repo, incident_manager=incident_mgr)

    # Clean dataset with stable distribution across features
    import numpy as np
    np.random.seed(42)
    balances = np.random.normal(250.0, 15.0, 80).round(2)
    activities = np.random.randint(1, 10, 80)
    clean_csv = (
        "id,user,balance,activity_count\n"
        + "\n".join([f"{i+1},user_{i+1},{balances[i]},{activities[i]}" for i in range(80)])
    ).encode("utf-8")
    df, _ = service.parse_file(clean_csv, "clean_crm.csv")
    ds = service.save_dataset("Clean CRM Ingest", "clean_crm.csv", df, clean_csv)

    result = service.execute_pipeline_on_dataset(ds.id, actor="admin")
    assert result["status"] == "SUCCESS"
    assert result["quality_score"] >= 80.0
    assert len(result["stages"]) == 5
    assert result["incident_code"] is None
    assert result["clean_path"] is not None


def test_pipeline_execution_on_corrupted_dataset_triggers_incident():
    repo = DataGuardRepository()
    notifier = NotificationDispatcher()
    incident_mgr = IncidentManager(repo=repo, notifier=notifier)
    service = DatasetService(repo=repo, incident_manager=incident_mgr)

    # Corrupted dataset (extreme null spike in balance: 80% null)
    rows = ["id,user,balance"]
    for i in range(50):
        val = "" if i < 40 else "100.0"
        rows.append(f"{i},user_{i},{val}")
    corrupt_csv = "\n".join(rows).encode("utf-8")

    df, _ = service.parse_file(corrupt_csv, "corrupt_data.csv")
    ds = service.save_dataset("Corrupted Input", "corrupt_data.csv", df, corrupt_csv)

    result = service.execute_pipeline_on_dataset(ds.id, actor="admin")
    assert result["status"] == "FAILED"
    assert result["quality_score"] < 70.0
    assert result["incident_code"] is not None
    assert result["incident_code"].startswith("INC-")
    assert result["quarantine_path"] is not None
