"""Automated Data Quality & Schema Validation Engine for DataGuard.

Evaluates tabular datasets against Data Contracts:
- Schema Conformance (missing or unexpected columns)
- Null / Missingness Thresholds
- Primary Key Uniqueness & Duplicates
- Numeric Range Boundaries
- Categorical Domain Validation
- Quality Health Scoring (0% - 100%) and Corrupted Row Quarantine Identification
"""

from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
import pandas as pd
import numpy as np
from config.settings import DEFAULT_NULL_THRESHOLD_PCT, DEFAULT_DUPLICATE_THRESHOLD_PCT


@dataclass
class CheckDetail:
    check_name: str
    status: str  # 'PASSED', 'WARNING', 'FAILED'
    category: str  # 'SCHEMA', 'COMPLETENESS', 'UNIQUENESS', 'VALIDITY'
    message: str
    metric_value: Optional[float] = None
    threshold: Optional[float] = None
    affected_rows_count: int = 0


@dataclass
class QualityReport:
    pipeline_id: str
    is_valid: bool
    quality_score: float  # 0.0 to 100.0
    total_rows: int
    passed_count: int
    failed_count: int
    corrupted_indices: List[int]
    checks: List[CheckDetail]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "is_valid": self.is_valid,
            "quality_score": round(self.quality_score, 1),
            "total_rows": self.total_rows,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "corrupted_rows_count": len(self.corrupted_indices),
            "checks": [
                {
                    "check_name": c.check_name,
                    "status": c.status,
                    "category": c.category,
                    "message": c.message,
                    "metric_value": c.metric_value,
                    "threshold": c.threshold,
                    "affected_rows": c.affected_rows_count,
                }
                for c in self.checks
            ],
        }


# =====================================================================
# PIPELINE DATA CONTRACT DEFINITIONS
# =====================================================================

DATA_CONTRACTS: Dict[str, Dict[str, Any]] = {
    "crm_customers_etl": {
        "required_columns": [
            "customer_id",
            "name",
            "email",
            "signup_date",
            "country",
            "account_balance",
        ],
        "primary_key": "customer_id",
        "critical_not_null": ["customer_id", "email"],
        "numeric_ranges": {"account_balance": {"min": 0.0, "max": 100000.0}},
        "allowed_categories": {"country": ["US", "IN", "DE", "GB", "CA", "FR", "JP", "AU"]},
    },
    "billing_transactions_sync": {
        "required_columns": [
            "transaction_id",
            "customer_id",
            "amount",
            "currency",
            "status",
            "timestamp",
        ],
        "primary_key": "transaction_id",
        "critical_not_null": ["transaction_id", "customer_id", "amount"],
        "numeric_ranges": {"amount": {"min": 0.01, "max": 50000.0}},
        "allowed_categories": {
            "currency": ["USD", "EUR", "GBP", "INR"],
            "status": ["SUCCESS", "PENDING", "FAILED"],
        },
    },
}


class DataQualityEngine:
    """Executes rule-based data quality and schema assertions."""

    def __init__(self, contracts: Optional[Dict[str, Dict[str, Any]]] = None):
        self.contracts = contracts or DATA_CONTRACTS

    def evaluate(self, pipeline_id: str, df: pd.DataFrame) -> QualityReport:
        """Runs the complete suite of quality checks on a DataFrame.

        Args:
            pipeline_id: The identifier for the pipeline (e.g. 'crm_customers_etl')
            df: The dataset to evaluate

        Returns:
            QualityReport containing pass/fail flags, individual check details,
            and indices of corrupted rows for recovery.
        """
        contract = self.contracts.get(pipeline_id)
        if not contract:
            # Fallback for unknown pipelines: generic basic check
            return self._generic_evaluation(pipeline_id, df)

        checks: List[CheckDetail] = []
        corrupted_indices: Set[int] = set()

        # 1. Schema Conformance Check
        schema_passed, schema_check = self._check_schema(df, contract["required_columns"])
        checks.append(schema_check)

        if not schema_passed:
            # If critical schema check failed, we cannot reliably check column values
            return QualityReport(
                pipeline_id=pipeline_id,
                is_valid=False,
                quality_score=0.0,
                total_rows=len(df),
                passed_count=0,
                failed_count=1,
                corrupted_indices=list(range(len(df))),
                checks=checks,
            )

        # 2. Primary Key Uniqueness & Nullability
        pk_col = contract.get("primary_key")
        if pk_col and pk_col in df.columns:
            pk_checks, pk_corrupted = self._check_primary_key(df, pk_col)
            checks.extend(pk_checks)
            corrupted_indices.update(pk_corrupted)

        # 3. Completeness (Null Thresholds on Critical Columns)
        for col in contract.get("critical_not_null", []):
            if col in df.columns:
                null_check, null_corrupted = self._check_nulls(col, df)
                checks.append(null_check)
                corrupted_indices.update(null_corrupted)

        # 4. Numeric Range Violations
        for col, bounds in contract.get("numeric_ranges", {}).items():
            if col in df.columns:
                range_check, range_corrupted = self._check_ranges(col, df, bounds["min"], bounds["max"])
                checks.append(range_check)
                corrupted_indices.update(range_corrupted)

        # 5. Categorical Domain Validation
        for col, allowed_vals in contract.get("allowed_categories", {}).items():
            if col in df.columns:
                cat_check, cat_corrupted = self._check_categories(col, df, allowed_vals)
                checks.append(cat_check)
                corrupted_indices.update(cat_corrupted)

        # 6. Overall Health Score Calculation
        failed_checks = [c for c in checks if c.status == "FAILED"]
        warning_checks = [c for c in checks if c.status == "WARNING"]
        passed_checks = [c for c in checks if c.status == "PASSED"]

        # Base score 100. Deduct 25 per failed check, 10 per warning check.
        score_penalty = (len(failed_checks) * 25.0) + (len(warning_checks) * 10.0)
        quality_score = max(0.0, min(100.0, 100.0 - score_penalty))
        is_valid = len(failed_checks) == 0

        return QualityReport(
            pipeline_id=pipeline_id,
            is_valid=is_valid,
            quality_score=quality_score,
            total_rows=len(df),
            passed_count=len(passed_checks),
            failed_count=len(failed_checks) + len(warning_checks),
            corrupted_indices=sorted(list(corrupted_indices)),
            checks=checks,
        )

    # -----------------------------------------------------------------
    # INTERNAL CHECK IMPLEMENTATIONS
    # -----------------------------------------------------------------

    def _check_schema(
        self, df: pd.DataFrame, required_columns: List[str]
    ) -> (bool, CheckDetail):
        """Verifies that all required columns are present in the dataset."""
        df_cols = set(df.columns)
        req_cols = set(required_columns)
        missing_cols = req_cols - df_cols
        unexpected_cols = df_cols - req_cols

        if missing_cols:
            return False, CheckDetail(
                check_name="schema_conformance",
                status="FAILED",
                category="SCHEMA",
                message=f"Missing required columns: {sorted(list(missing_cols))}. Found unexpected: {sorted(list(unexpected_cols))}",
                affected_rows_count=len(df),
            )

        return True, CheckDetail(
            check_name="schema_conformance",
            status="PASSED",
            category="SCHEMA",
            message=f"All {len(required_columns)} required columns present.",
            affected_rows_count=0,
        )

    def _check_primary_key(
        self, df: pd.DataFrame, pk_col: str
    ) -> (List[CheckDetail], Set[int]):
        """Checks that the primary key has zero nulls and no duplicates."""
        checks = []
        corrupted = set()

        # Null PK check
        null_mask = df[pk_col].isna()
        null_count = int(null_mask.sum())
        if null_count > 0:
            checks.append(
                CheckDetail(
                    check_name=f"primary_key_nulls_{pk_col}",
                    status="FAILED",
                    category="COMPLETENESS",
                    message=f"Primary key '{pk_col}' contains {null_count} null values.",
                    affected_rows_count=null_count,
                )
            )
            corrupted.update(df[null_mask].index.tolist())
        else:
            checks.append(
                CheckDetail(
                    check_name=f"primary_key_nulls_{pk_col}",
                    status="PASSED",
                    category="COMPLETENESS",
                    message=f"Primary key '{pk_col}' has 0 missing values.",
                    affected_rows_count=0,
                )
            )

        # Duplicate PK check
        dup_mask = df.duplicated(subset=[pk_col], keep="first")
        dup_count = int(dup_mask.sum())
        dup_pct = (dup_count / len(df)) * 100 if len(df) > 0 else 0.0

        if dup_pct > DEFAULT_DUPLICATE_THRESHOLD_PCT:
            status = "FAILED"
        elif dup_count > 0:
            status = "WARNING"
        else:
            status = "PASSED"

        checks.append(
            CheckDetail(
                check_name=f"primary_key_uniqueness_{pk_col}",
                status=status,
                category="UNIQUENESS",
                message=f"Primary key '{pk_col}' duplicate rate: {dup_pct:.1f}% ({dup_count} duplicate rows).",
                metric_value=dup_pct,
                threshold=DEFAULT_DUPLICATE_THRESHOLD_PCT,
                affected_rows_count=dup_count,
            )
        )
        if dup_count > 0:
            corrupted.update(df[dup_mask].index.tolist())

        return checks, corrupted

    def _check_nulls(
        self, col: str, df: pd.DataFrame
    ) -> (CheckDetail, Set[int]):
        """Checks whether null percentage exceeds allowable threshold."""
        null_mask = df[col].isna()
        null_count = int(null_mask.sum())
        null_pct = (null_count / len(df)) * 100 if len(df) > 0 else 0.0

        if null_pct > DEFAULT_NULL_THRESHOLD_PCT:
            return (
                CheckDetail(
                    check_name=f"null_rate_{col}",
                    status="FAILED",
                    category="COMPLETENESS",
                    message=f"Null spike detected in '{col}': {null_pct:.1f}% missing (threshold: {DEFAULT_NULL_THRESHOLD_PCT}%).",
                    metric_value=round(null_pct, 2),
                    threshold=DEFAULT_NULL_THRESHOLD_PCT,
                    affected_rows_count=null_count,
                ),
                set(df[null_mask].index.tolist()),
            )

        return (
            CheckDetail(
                check_name=f"null_rate_{col}",
                status="PASSED",
                category="COMPLETENESS",
                message=f"Null rate in '{col}' acceptable: {null_pct:.1f}% (threshold: {DEFAULT_NULL_THRESHOLD_PCT}%).",
                metric_value=round(null_pct, 2),
                threshold=DEFAULT_NULL_THRESHOLD_PCT,
                affected_rows_count=null_count,
            ),
            set(),
        )

    def _check_ranges(
        self, col: str, df: pd.DataFrame, min_val: float, max_val: float
    ) -> (CheckDetail, Set[int]):
        """Asserts that numerical values reside within expected logical boundaries."""
        clean_series = pd.to_numeric(df[col], errors="coerce")
        out_of_bounds_mask = (clean_series < min_val) | (clean_series > max_val)
        violation_count = int(out_of_bounds_mask.sum())

        if violation_count > 0:
            return (
                CheckDetail(
                    check_name=f"range_boundary_{col}",
                    status="FAILED",
                    category="VALIDITY",
                    message=f"Found {violation_count} rows out of bounds in '{col}' [allowed: {min_val} to {max_val}].",
                    metric_value=float(violation_count),
                    threshold=0.0,
                    affected_rows_count=violation_count,
                ),
                set(df[out_of_bounds_mask].index.tolist()),
            )

        return (
            CheckDetail(
                check_name=f"range_boundary_{col}",
                status="PASSED",
                category="VALIDITY",
                message=f"All values in '{col}' fall within acceptable bounds [{min_val} to {max_val}].",
                metric_value=0.0,
                threshold=0.0,
                affected_rows_count=0,
            ),
            set(),
        )

    def _check_categories(
        self, col: str, df: pd.DataFrame, allowed_vals: List[str]
    ) -> (CheckDetail, Set[int]):
        """Asserts that categorical values match the allowable domain."""
        invalid_mask = (~df[col].isna()) & (~df[col].isin(allowed_vals))
        invalid_count = int(invalid_mask.sum())

        if invalid_count > 0:
            return (
                CheckDetail(
                    check_name=f"category_domain_{col}",
                    status="FAILED",
                    category="VALIDITY",
                    message=f"Found {invalid_count} illegal categories in '{col}' not in allowed set.",
                    metric_value=float(invalid_count),
                    threshold=0.0,
                    affected_rows_count=invalid_count,
                ),
                set(df[invalid_mask].index.tolist()),
            )

        return (
            CheckDetail(
                check_name=f"category_domain_{col}",
                status="PASSED",
                category="VALIDITY",
                message=f"All categories in '{col}' conform to allowed domain.",
                metric_value=0.0,
                threshold=0.0,
                affected_rows_count=0,
            ),
            set(),
        )

    def _generic_evaluation(self, pipeline_id: str, df: pd.DataFrame) -> QualityReport:
        """Fallback evaluation for pipelines without explicit data contracts."""
        null_count = int(df.isna().sum().sum())
        return QualityReport(
            pipeline_id=pipeline_id,
            is_valid=True,
            quality_score=95.0,
            total_rows=len(df),
            passed_count=1,
            failed_count=0,
            corrupted_indices=[],
            checks=[
                CheckDetail(
                    check_name="generic_row_count",
                    status="PASSED",
                    category="VALIDITY",
                    message=f"Generic check passed with {len(df)} rows and {null_count} total nulls.",
                )
            ],
        )
