"""Unit tests for DataQualityEngine.

Verifies schema contract enforcement, missingness checks, primary key uniqueness,
numeric range boundary validation, and health score calculations.
"""

import pytest
import pandas as pd
from src.core.quality_engine import DataQualityEngine
from src.core.simulator import PipelineSimulator


def test_clean_crm_data_passes_all_checks():
    """Verifies that clean CRM data passes with a perfect 100% quality score."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=250, fault_type=None)

    engine = DataQualityEngine()
    report = engine.evaluate("crm_customers_etl", df)

    assert report.is_valid is True
    assert report.quality_score == 100.0
    assert report.failed_count == 0
    assert len(report.corrupted_indices) == 0


def test_schema_mismatch_fails_critically():
    """Verifies that schema breaking changes result in immediate validation failure."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=100, fault_type="SCHEMA_MISMATCH")

    engine = DataQualityEngine()
    report = engine.evaluate("crm_customers_etl", df)

    assert report.is_valid is False
    assert report.quality_score == 0.0
    schema_checks = [c for c in report.checks if c.check_name == "schema_conformance"]
    assert len(schema_checks) == 1
    assert schema_checks[0].status == "FAILED"
    assert "Missing required columns" in schema_checks[0].message


def test_null_spike_detection():
    """Verifies that high missingness is flagged as a failure."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=300, fault_type="NULL_SPIKE")

    engine = DataQualityEngine()
    report = engine.evaluate("crm_customers_etl", df)

    assert report.is_valid is False
    assert report.quality_score < 100.0
    failed_checks = [c.check_name for c in report.checks if c.status == "FAILED"]
    assert "null_rate_email" in failed_checks
    assert len(report.corrupted_indices) > 0


def test_numerical_range_and_category_violations():
    """Verifies that negative balances and corrupt country strings are flagged and isolated."""
    simulator = PipelineSimulator()
    df = simulator.generate_crm_data(num_rows=200, fault_type="ANOMALY_VALUES")

    engine = DataQualityEngine()
    report = engine.evaluate("crm_customers_etl", df)

    assert report.is_valid is False
    failed_checks = [c.check_name for c in report.checks if c.status == "FAILED"]
    assert "range_boundary_account_balance" in failed_checks
    assert "category_domain_country" in failed_checks
    assert len(report.corrupted_indices) > 0


def test_billing_clean_transactions_pass():
    """Verifies that clean billing transactions pass contracts."""
    simulator = PipelineSimulator()
    df = simulator.generate_billing_data(num_rows=150, fault_type=None)

    engine = DataQualityEngine()
    report = engine.evaluate("billing_transactions_sync", df)

    assert report.is_valid is True
    assert report.quality_score == 100.0
