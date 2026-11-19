"""Quality, Drift & SLA Contracts - Owned by Member 4 (Data Quality & Detection Engineer)."""

from typing import Protocol, Dict, Any, List, Optional
import pandas as pd


class IQualityEngine(Protocol):
    """Contract for data quality evaluation, scoring, and grading."""

    def evaluate(
        self,
        df: pd.DataFrame,
        pipeline_id: str,
        rules: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Evaluates DataFrame against quality rules, returning scores, grades, and rule breakdowns."""
        ...


class IDriftDetector(Protocol):
    """Contract for schema and statistical distribution drift detection."""

    def evaluate(
        self,
        baseline_df: pd.DataFrame,
        current_df: pd.DataFrame,
        feature_cols: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Calculates drift metrics, PSI, and detected anomalies between datasets."""
        ...

    def calculate_psi(
        self,
        baseline_series: pd.Series,
        current_series: pd.Series,
        num_buckets: int = 10,
    ) -> float:
        """Calculates Population Stability Index between baseline and current distributions."""
        ...

    def calculate_ks_drift(
        self,
        baseline_series: pd.Series,
        current_series: pd.Series,
    ) -> Dict[str, Any]:
        """Performs two-sample Kolmogorov-Smirnov distribution test."""
        ...


class ISLAMonitor(Protocol):
    """Contract for SLA latency monitoring and breach identification."""

    def evaluate_run_sla(
        self,
        pipeline_id: str,
        duration_seconds: float,
        record_count: int = 0,
        run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluates execution duration against pipeline SLA limits."""
        ...

    def get_pipeline_compliance(
        self,
        pipeline_id: str,
        window_days: int = 30,
    ) -> Dict[str, Any]:
        """Calculates SLA compliance percentage over historical runs."""
        ...
