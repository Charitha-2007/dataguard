"""Extended edge-case tests for DatasetService.

Additional scenarios beyond the baseline 7 tests:
- Empty CSV (0 rows)
- 100% null column
- 95% duplicate rows
- All-string columns (no numerics)
- Binary file renamed to .csv
- Large 1000-row CSV (triggers drift analysis ≥150 rows)
- Multi-upload simulation (upload 3 datasets sequentially)
"""

import io
import json
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

TEST_DB_PATH = DATA_DIR / "test_dataguard_extended.db"


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


# ─────────────────────────────────────────────────────────────────────────────
# TEST 1 — Empty CSV (0 data rows, header only)
# ─────────────────────────────────────────────────────────────────────────────
def test_empty_csv_raises_value_error():
    """A CSV with header but zero data rows must raise ValueError containing 'empty'."""
    service = DatasetService()
    empty_csv = b"id,name,amount\n"
    with pytest.raises(ValueError, match="empty"):
        service.parse_file(empty_csv, "empty_data.csv")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 2 — Completely empty bytes
# ─────────────────────────────────────────────────────────────────────────────
def test_zero_byte_file_raises_value_error():
    """A completely empty file (0 bytes) must raise ValueError."""
    service = DatasetService()
    with pytest.raises(ValueError):
        service.parse_file(b"", "nothing.csv")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 3 — 100% null column
# ─────────────────────────────────────────────────────────────────────────────
def test_hundred_percent_null_column_detected():
    """A column with 100% null values should be detected in profiling."""
    service = DatasetService()
    rows = ["id,revenue,category"]
    for i in range(30):
        rows.append(f"{i},,cat_a")
    csv_bytes = "\n".join(rows).encode("utf-8")

    df, _ = service.parse_file(csv_bytes, "null_col.csv")
    profile = service.profile_dataset(df, "null_col")

    assert profile["missing_by_column"]["revenue"]["count"] == 30
    assert profile["missing_by_column"]["revenue"]["percentage"] == 100.0
    assert profile["quality_score"] < 70.0  # Must be flagged unhealthy


# ─────────────────────────────────────────────────────────────────────────────
# TEST 4 — 95% duplicate rows
# ─────────────────────────────────────────────────────────────────────────────
def test_high_duplicate_ratio_detected():
    """A dataset where 95% of rows are identical should report high duplicates."""
    service = DatasetService()
    rows = ["id,name,value"]
    # 2 unique rows + 38 duplicates = 40 total, 38 dups = 95%
    rows.append("1,Alice,100")
    rows.append("2,Bob,200")
    for _ in range(38):
        rows.append("1,Alice,100")
    csv_bytes = "\n".join(rows).encode("utf-8")

    df, _ = service.parse_file(csv_bytes, "dupes.csv")
    profile = service.profile_dataset(df, "dupes")

    assert profile["duplicate_total"] >= 38
    assert profile["duplicate_pct"] >= 90.0
    assert profile["quality_score"] < 80.0  # Duplicate penalty applied


# ─────────────────────────────────────────────────────────────────────────────
# TEST 5 — All-string columns (no numeric columns)
# ─────────────────────────────────────────────────────────────────────────────
def test_all_string_columns_profiled_without_error():
    """A dataset with no numeric columns should profile cleanly (no outlier crash)."""
    service = DatasetService()
    rows = ["country,city,status,category"]
    for i in range(20):
        rows.append(f"India,City_{i},active,cat_{i % 3}")
    csv_bytes = "\n".join(rows).encode("utf-8")

    df, meta = service.parse_file(csv_bytes, "text_only.csv")
    assert meta["column_count"] == 4

    profile = service.profile_dataset(df, "text_only")
    assert profile["total_rows"] == 20
    assert profile["numeric_columns"] == []
    assert profile["total_outliers"] == 0  # No numerics → no outliers
    assert profile["quality_score"] > 80.0  # Clean text dataset


# ─────────────────────────────────────────────────────────────────────────────
# TEST 6 — Binary/garbage content renamed to .csv
# ─────────────────────────────────────────────────────────────────────────────
def test_binary_file_disguised_as_csv_raises_error():
    """A binary file with .csv extension should fail to parse with a clear error."""
    service = DatasetService()
    # Simulate binary content (e.g. PNG header bytes)
    binary_content = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] * 100)

    with pytest.raises((ValueError, Exception)):
        service.parse_file(binary_content, "fake_data.csv")


# ─────────────────────────────────────────────────────────────────────────────
# TEST 7 — Large 1000-row CSV (triggers drift analysis path ≥150 rows)
# ─────────────────────────────────────────────────────────────────────────────
def test_large_dataset_full_pipeline_with_drift_analysis():
    """A 1000-row clean dataset should trigger drift analysis and pass the pipeline."""
    repo = DataGuardRepository()
    notifier = NotificationDispatcher()
    incident_mgr = IncidentManager(repo=repo, notifier=notifier)
    service = DatasetService(repo=repo, incident_manager=incident_mgr)

    np.random.seed(0)
    n = 1000
    rows = ["order_id,amount,quantity,discount"]
    for i in range(n):
        amt = round(np.random.normal(500.0, 50.0), 2)
        qty = int(np.random.randint(1, 20))
        disc = round(np.random.uniform(0, 0.3), 3)
        rows.append(f"ORD-{i:05d},{amt},{qty},{disc}")

    csv_bytes = "\n".join(rows).encode("utf-8")
    df, meta = service.parse_file(csv_bytes, "large_orders.csv")

    assert len(df) == 1000
    assert meta["column_count"] == 4

    ds = service.save_dataset("Large Orders Batch", "large_orders.csv", df, csv_bytes, actor="admin")
    assert ds.row_count == 1000

    result = service.execute_pipeline_on_dataset(ds.id, actor="admin")
    assert result["status"] == "SUCCESS"
    assert result["quality_score"] >= 80.0
    assert len(result["stages"]) == 5


# ─────────────────────────────────────────────────────────────────────────────
# TEST 8 — Multi-dataset upload simulation (3 sequential uploads)
# ─────────────────────────────────────────────────────────────────────────────
def test_multi_dataset_upload_independent_catalog_entries():
    """Upload 3 different datasets; each should get a unique ID and coexist in catalog."""
    repo = DataGuardRepository()
    service = DatasetService(repo=repo)

    datasets_to_upload = [
        (b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n", "batch_a.csv", "Batch A"),
        (b"x,y\n10,20\n30,40\n50,60\n", "batch_b.csv", "Batch B"),
        (b"p,q,r,s\n1,A,0.1,yes\n2,B,0.2,no\n3,C,0.3,yes\n", "batch_c.csv", "Batch C"),
    ]

    saved_ids = []
    for raw, fname, dname in datasets_to_upload:
        df, _ = service.parse_file(raw, fname)
        ds = service.save_dataset(dname, fname, df, raw, actor="admin")
        saved_ids.append(ds.id)

    # All 3 should be unique IDs
    assert len(set(saved_ids)) == 3

    # All 3 should be retrievable
    all_ds = service.get_all_datasets()
    catalog_ids = {d["id"] for d in all_ds}
    for sid in saved_ids:
        assert sid in catalog_ids


# ─────────────────────────────────────────────────────────────────────────────
# TEST 9 — JSON with nested objects (should flatten or raise gracefully)
# ─────────────────────────────────────────────────────────────────────────────
def test_json_array_of_flat_records_parsed_correctly():
    """A valid JSON array of flat dicts should be parsed into a DataFrame."""
    service = DatasetService()
    records = [{"id": i, "score": i * 1.5, "label": f"L{i}"} for i in range(10)]
    json_bytes = json.dumps(records).encode("utf-8")

    df, meta = service.parse_file(json_bytes, "records.json")
    assert len(df) == 10
    assert "score" in df.columns
    assert meta["file_type"] == "json"


# ─────────────────────────────────────────────────────────────────────────────
# TEST 10 — Unsupported file extension
# ─────────────────────────────────────────────────────────────────────────────
def test_unsupported_file_format_raises_error():
    """A .parquet or .txt file should raise ValueError with 'Unsupported'."""
    service = DatasetService()
    for bad_name in ["data.parquet", "log.txt", "dump.xml"]:
        with pytest.raises(ValueError, match="Unsupported"):
            service.parse_file(b"some content here", bad_name)
