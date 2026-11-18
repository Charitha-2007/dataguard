"""Unit tests for Root Cause Analysis (RCA) and Downstream Impact (DAG) Engine.

Verifies automated diagnosis classification, severity assignment (P1 to P4),
recovery recommendation inference, and DAG blast radius traversal.
"""

import pytest
from config.settings import DATA_DIR, DATABASE_PATH
from src.database.connection import set_database_path, get_db
from src.database.models import init_db
from src.database.repository import DataGuardRepository
from src.core.rca_engine import RootCauseAnalysisEngine
from src.core.impact_analyzer import DependencyImpactAnalyzer
from src.core.quality_engine import DataQualityEngine
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


# =====================================================================
# ROOT CAUSE ANALYSIS (RCA) TESTS
# =====================================================================

def test_rca_diagnoses_runtime_crash():
    """Verifies that unhandled exceptions are diagnosed as P1 RUNTIME_EXCEPTION."""
    engine = RootCauseAnalysisEngine()
    diagnosis = engine.diagnose(
        pipeline_id="crm_customers_etl",
        sla_seconds=180,
        duration_seconds=5.2,
        row_count=0,
        error_message="OperationalError: database disk image is malformed",
    )

    assert diagnosis is not None
    assert diagnosis.incident_type == "RUNTIME_EXCEPTION"
    assert diagnosis.severity == "P1"
    assert diagnosis.recommended_action == "RETRY"


def test_rca_diagnoses_schema_mismatch():
    """Verifies that missing columns are diagnosed as P1 SCHEMA_MISMATCH with SCHEMA_PATCH."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=100, fault_type="SCHEMA_MISMATCH")

    quality_engine = DataQualityEngine()
    report = quality_engine.evaluate("crm_customers_etl", df)

    rca_engine = RootCauseAnalysisEngine()
    diagnosis = rca_engine.diagnose(
        pipeline_id="crm_customers_etl",
        sla_seconds=180,
        duration_seconds=20.0,
        row_count=len(df),
        quality_report=report,
    )

    assert diagnosis is not None
    assert diagnosis.incident_type == "SCHEMA_MISMATCH"
    assert diagnosis.severity == "P1"
    assert diagnosis.recommended_action == "SCHEMA_PATCH"


def test_rca_diagnoses_sla_breach():
    """Verifies that excessive run duration triggers P1/P2 SLA_BREACH."""
    rca_engine = RootCauseAnalysisEngine()
    # SLA is 180s, duration took 400s
    diagnosis = rca_engine.diagnose(
        pipeline_id="crm_customers_etl",
        sla_seconds=180,
        duration_seconds=400.0,
        row_count=500,
    )

    assert diagnosis is not None
    assert diagnosis.incident_type == "SLA_BREACH"
    assert diagnosis.recommended_action == "RETRY"
    assert "SLA breached by" in diagnosis.title


def test_rca_diagnoses_null_spike():
    """Verifies that null spikes are diagnosed as P2 NULL_SPIKE with DROP_CORRUPTED."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=200, fault_type="NULL_SPIKE")

    quality_engine = DataQualityEngine()
    report = quality_engine.evaluate("crm_customers_etl", df)

    rca_engine = RootCauseAnalysisEngine()
    diagnosis = rca_engine.diagnose(
        pipeline_id="crm_customers_etl",
        sla_seconds=180,
        duration_seconds=15.0,
        row_count=len(df),
        quality_report=report,
    )

    assert diagnosis is not None
    assert diagnosis.incident_type == "NULL_SPIKE"
    assert diagnosis.severity == "P2"
    assert diagnosis.recommended_action == "DROP_CORRUPTED"


def test_rca_returns_none_for_healthy_run():
    """Verifies that a clean, healthy run produces no diagnosis (None)."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=200, fault_type=None)

    quality_engine = DataQualityEngine()
    report = quality_engine.evaluate("crm_customers_etl", df)

    rca_engine = RootCauseAnalysisEngine()
    diagnosis = rca_engine.diagnose(
        pipeline_id="crm_customers_etl",
        sla_seconds=180,
        duration_seconds=25.0,
        row_count=len(df),
        quality_report=report,
    )

    assert diagnosis is None


# =====================================================================
# DOWNSTREAM DAG IMPACT TESTS
# =====================================================================

def test_impact_analyzer_detects_downstream_blocker():
    """Verifies that failure in crm_customers_etl reports warehouse_finance_mart as blocked."""
    repo = DataGuardRepository()
    analyzer = DependencyImpactAnalyzer(repo=repo)

    impact = analyzer.analyze_impact("crm_customers_etl")

    assert impact.total_impacted_pipelines >= 1
    assert "warehouse_finance_mart" in impact.direct_dependents
    assert impact.blast_radius_score in ["MEDIUM", "HIGH"]
    assert len(impact.graph_edges) >= 1


def test_impact_analyzer_on_leaf_pipeline():
    """Verifies that failure in a leaf pipeline (warehouse_finance_mart) has zero dependents."""
    repo = DataGuardRepository()
    analyzer = DependencyImpactAnalyzer(repo=repo)

    impact = analyzer.analyze_impact("warehouse_finance_mart")

    assert impact.total_impacted_pipelines == 0
    assert impact.blast_radius_score == "NONE"
    assert len(impact.direct_dependents) == 0
