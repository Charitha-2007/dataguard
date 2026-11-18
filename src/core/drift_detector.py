"""Statistical Data Drift & ML Anomaly Detection Engine for DataGuard.

Implements:
1. Population Stability Index (PSI) for distributional divergence.
2. Two-sample Kolmogorov-Smirnov (KS) test for non-parametric continuous drift.
3. Scikit-Learn Isolation Forest for multivariate row-level anomaly detection.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import numpy as np
import pandas as pd
from scipy import stats
from sklearn.ensemble import IsolationForest

from config.settings import DEFAULT_DRIFT_THRESHOLD_PVAL, DEFAULT_PSI_DRIFT_THRESHOLD


@dataclass
class ColumnDriftResult:
    column: str
    psi_score: float
    ks_statistic: float
    ks_pvalue: float
    is_drift_detected: bool
    drift_severity: str  # 'NONE', 'MODERATE', 'CRITICAL'
    message: str


@dataclass
class AnomalyResult:
    total_rows: int
    anomaly_count: int
    anomaly_percentage: float
    anomaly_indices: List[int]
    is_anomaly_detected: bool
    message: str


@dataclass
class DriftAnomalyReport:
    pipeline_id: str
    has_drift_or_anomaly: bool
    column_drifts: Dict[str, ColumnDriftResult]
    multivariate_anomaly: AnomalyResult
    overall_status: str  # 'HEALTHY', 'DRIFT_WARNING', 'CRITICAL_DRIFT'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "has_drift_or_anomaly": self.has_drift_or_anomaly,
            "overall_status": self.overall_status,
            "column_drifts": {col: asdict(res) for col, res in self.column_drifts.items()},
            "multivariate_anomaly": asdict(self.multivariate_anomaly),
        }


class DriftAnomalyDetector:
    """Detects statistical shift between baseline and current data batches."""

    def __init__(
        self,
        psi_threshold: float = DEFAULT_PSI_DRIFT_THRESHOLD,
        ks_pval_threshold: float = DEFAULT_DRIFT_THRESHOLD_PVAL,
    ):
        self.psi_threshold = psi_threshold
        self.ks_pval_threshold = ks_pval_threshold

    # -----------------------------------------------------------------
    # 1. POPULATION STABILITY INDEX (PSI)
    # -----------------------------------------------------------------

    def calculate_psi(
        self,
        reference: pd.Series,
        current: pd.Series,
        num_bins: int = 10,
    ) -> float:
        """Calculates Population Stability Index between reference and current series.

        Formula:
            PSI = SUM( (Actual_i - Expected_i) * ln(Actual_i / Expected_i) )

        Interpretation:
            PSI < 0.1  : No significant distribution change.
            0.1 <= PSI < 0.2: Moderate shift (Warning).
            PSI >= 0.2 : Significant data drift (Critical Alert).
        """
        ref_clean = reference.dropna().to_numpy()
        cur_clean = current.dropna().to_numpy()

        if len(ref_clean) < 10 or len(cur_clean) < 10:
            return 0.0

        # Create quantile-based bins from reference distribution
        percentiles = np.linspace(0, 100, num_bins + 1)
        bin_edges = np.percentile(ref_clean, percentiles)
        
        # Extend outer edges to cover the combined range of both distributions
        bin_edges[0] = min(float(ref_clean.min()), float(cur_clean.min())) - 1e-4
        bin_edges[-1] = max(float(ref_clean.max()), float(cur_clean.max())) + 1e-4
        bin_edges = np.unique(bin_edges)

        if len(bin_edges) < 2:
            return 0.0

        # Calculate frequency distribution in bins
        ref_counts, _ = np.histogram(ref_clean, bins=bin_edges)
        cur_counts, _ = np.histogram(cur_clean, bins=bin_edges)

        # Convert to percentages with epsilon smoothing to prevent div by zero
        eps = 1e-4
        ref_pct = (ref_counts / len(ref_clean)) + eps
        cur_pct = (cur_counts / len(cur_clean)) + eps

        # Normalize
        ref_pct /= np.sum(ref_pct)
        cur_pct /= np.sum(cur_pct)

        # Calculate PSI
        psi_val = np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct))
        return round(float(psi_val), 4)

    # -----------------------------------------------------------------
    # 2. KOLMOGOROV-SMIRNOV (KS) DRIFT TEST
    # -----------------------------------------------------------------

    def calculate_ks_drift(
        self, reference: pd.Series, current: pd.Series
    ) -> Tuple[float, float, bool]:
        """Runs the two-sample KS test.

        Returns:
            Tuple of (ks_statistic, p_value, is_drift_detected)
            If p_value < ks_pval_threshold (0.05), drift is statistically confirmed.
        """
        ref_clean = reference.dropna()
        cur_clean = current.dropna()

        if len(ref_clean) < 5 or len(cur_clean) < 5:
            return 0.0, 1.0, False

        res = stats.ks_2samp(ref_clean, cur_clean)
        ks_stat = round(float(res.statistic), 4)
        p_val = round(float(res.pvalue), 4)
        is_drift = bool(p_val < self.ks_pval_threshold)

        return ks_stat, p_val, is_drift

    # -----------------------------------------------------------------
    # 3. SCIKIT-LEARN ISOLATION FOREST MULTIVARIATE ANOMALY DETECTION
    # -----------------------------------------------------------------

    def detect_multivariate_anomalies(
        self,
        df: pd.DataFrame,
        numeric_columns: List[str],
        contamination: float = 0.05,
    ) -> AnomalyResult:
        """Applies an Isolation Forest model to detect multivariate outliers.

        Args:
            df: DataFrame to inspect
            numeric_columns: Numeric feature columns to feed to Isolation Forest
            contamination: Expected proportion of outliers in the data (default 5%)

        Returns:
            AnomalyResult with anomaly count, percentage, and row indices.
        """
        valid_cols = [c for c in numeric_columns if c in df.columns]
        if not valid_cols or len(df) < 15:
            return AnomalyResult(
                total_rows=len(df),
                anomaly_count=0,
                anomaly_percentage=0.0,
                anomaly_indices=[],
                is_anomaly_detected=False,
                message="Insufficient rows or numeric features for Isolation Forest.",
            )

        # Fill NaNs temporarily for Isolation Forest evaluation
        features = df[valid_cols].fillna(df[valid_cols].median())

        iso_forest = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
        )
        # -1 = anomaly, 1 = normal
        predictions = iso_forest.fit_predict(features)
        anomaly_mask = predictions == -1
        anomaly_indices = df[anomaly_mask].index.tolist()
        anomaly_count = len(anomaly_indices)
        anomaly_pct = round((anomaly_count / len(df)) * 100, 2)

        is_anomaly = anomaly_pct > (contamination * 100 * 1.5)  # More than 1.5x expected rate

        msg = (
            f"Isolation Forest flagged {anomaly_count} outliers ({anomaly_pct}% of batch)."
            if anomaly_count > 0
            else "No multivariate anomalies detected."
        )

        return AnomalyResult(
            total_rows=len(df),
            anomaly_count=anomaly_count,
            anomaly_percentage=anomaly_pct,
            anomaly_indices=anomaly_indices,
            is_anomaly_detected=is_anomaly,
            message=msg,
        )

    # -----------------------------------------------------------------
    # 4. COMPREHENSIVE PIPELINE EVALUATION
    # -----------------------------------------------------------------

    def evaluate(
        self,
        pipeline_id: str,
        reference_df: pd.DataFrame,
        current_df: pd.DataFrame,
        numeric_columns: List[str],
    ) -> DriftAnomalyReport:
        """Runs PSI, KS-test, and Isolation Forest on current batch vs baseline."""
        column_drifts: Dict[str, ColumnDriftResult] = {}
        has_critical_drift = False
        has_moderate_drift = False

        for col in numeric_columns:
            if col in reference_df.columns and col in current_df.columns:
                ref_series = pd.to_numeric(reference_df[col], errors="coerce")
                cur_series = pd.to_numeric(current_df[col], errors="coerce")

                psi = self.calculate_psi(ref_series, cur_series)
                ks_stat, ks_pval, is_ks_drift = self.calculate_ks_drift(ref_series, cur_series)

                if psi >= self.psi_threshold or (is_ks_drift and psi >= 0.15):
                    severity = "CRITICAL"
                    has_critical_drift = True
                    msg = f"Critical drift detected in '{col}': PSI={psi} (threshold: {self.psi_threshold}), KS p-val={ks_pval:.4f}."
                    is_drift = True
                elif psi >= 0.10 or is_ks_drift:
                    severity = "MODERATE"
                    has_moderate_drift = True
                    msg = f"Moderate distributional shift in '{col}': PSI={psi}, KS p-val={ks_pval:.4f}."
                    is_drift = True
                else:
                    severity = "NONE"
                    msg = f"Distribution for '{col}' is stable: PSI={psi}, KS p-val={ks_pval:.4f}."
                    is_drift = False

                column_drifts[col] = ColumnDriftResult(
                    column=col,
                    psi_score=psi,
                    ks_statistic=ks_stat,
                    ks_pvalue=ks_pval,
                    is_drift_detected=is_drift,
                    drift_severity=severity,
                    message=msg,
                )

        # Run Isolation Forest multivariate outlier detection
        iso_result = self.detect_multivariate_anomalies(
            current_df, numeric_columns=numeric_columns
        )

        if has_critical_drift or iso_result.is_anomaly_detected:
            overall_status = "CRITICAL_DRIFT"
        elif has_moderate_drift:
            overall_status = "DRIFT_WARNING"
        else:
            overall_status = "HEALTHY"

        has_drift_or_anomaly = overall_status != "HEALTHY"

        return DriftAnomalyReport(
            pipeline_id=pipeline_id,
            has_drift_or_anomaly=has_drift_or_anomaly,
            column_drifts=column_drifts,
            multivariate_anomaly=iso_result,
            overall_status=overall_status,
        )
