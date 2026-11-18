"""Unit tests for DriftAnomalyDetector.

Verifies Population Stability Index (PSI) calculations, two-sample KS hypothesis tests,
Scikit-Learn Isolation Forest outlier detection, and comprehensive pipeline drift reports.
"""

import pytest
import numpy as np
import pandas as pd
from src.core.drift_detector import DriftAnomalyDetector
from src.core.simulator import PipelineSimulator


def test_psi_identical_distributions():
    """Verifies that samples from identical distributions produce a low PSI (< 0.05)."""
    np.random.seed(42)
    s1 = pd.Series(np.random.normal(loc=100, scale=15, size=1000))
    s2 = pd.Series(np.random.normal(loc=100, scale=15, size=1000))

    detector = DriftAnomalyDetector()
    psi = detector.calculate_psi(s1, s2)

    assert psi < 0.08  # Should be near zero for identical distributions


def test_psi_and_ks_shifted_distribution():
    """Verifies that a significant distributional shift triggers high PSI and low KS p-value."""
    np.random.seed(42)
    ref = pd.Series(np.random.normal(loc=50, scale=10, size=500))
    # Target distribution shifted to mean=120
    cur = pd.Series(np.random.normal(loc=120, scale=10, size=500))

    detector = DriftAnomalyDetector()
    psi = detector.calculate_psi(ref, cur)
    ks_stat, p_val, is_drift = detector.calculate_ks_drift(ref, cur)

    assert psi >= 0.20  # Significant drift
    assert is_drift is True
    assert p_val < 0.001


def test_isolation_forest_flags_outliers():
    """Verifies that Isolation Forest flags injected multivariate anomalies."""
    np.random.seed(42)
    normal_data = np.random.normal(loc=50, scale=5, size=(300, 2))
    df = pd.DataFrame(normal_data, columns=["feature_a", "feature_b"])

    # Inject a cluster of extreme multivariate outliers
    outliers = np.array([[500.0, -500.0], [999.0, 999.0], [-300.0, 800.0]])
    df_outliers = pd.DataFrame(outliers, columns=["feature_a", "feature_b"])
    df = pd.concat([df, df_outliers], ignore_index=True)

    detector = DriftAnomalyDetector()
    result = detector.detect_multivariate_anomalies(
        df, numeric_columns=["feature_a", "feature_b"], contamination=0.03
    )

    assert result.anomaly_count >= 3
    # The last 3 row indices should be flagged as anomalies
    assert (len(df) - 1) in result.anomaly_indices


def test_end_to_end_pipeline_drift_evaluation():
    """Verifies complete drift report on simulated CRM pipeline datasets."""
    simulator = PipelineSimulator()
    ref_df = simulator.generate_crm_data(num_rows=400, fault_type=None)
    
    # Current batch with shifted balance (all balances multiplied by 10)
    cur_df = simulator.generate_crm_data(num_rows=400, fault_type=None)
    cur_df["account_balance"] = cur_df["account_balance"] * 10.0

    detector = DriftAnomalyDetector()
    report = detector.evaluate(
        pipeline_id="crm_customers_etl",
        reference_df=ref_df,
        current_df=cur_df,
        numeric_columns=["account_balance"],
    )

    assert report.has_drift_or_anomaly is True
    assert "account_balance" in report.column_drifts
    balance_drift = report.column_drifts["account_balance"]
    assert balance_drift.is_drift_detected is True
    assert balance_drift.drift_severity in ["MODERATE", "CRITICAL"]
