"""Dataset Cleaning & Export Engine for DataGuard.

Implements enterprise data preprocessing, sanitization, and export workflows:
- Duplicate detection and removal
- Smart missing-value imputation (median for numeric, mode for categorical) or dropping
- Statistical IQR outlier filtering and boundary clipping
- String whitespace trimming and column normalization
- Pre-cleaning vs post-cleaning telemetry and quality score improvement
- High-performance binary exports for CSV (UTF-8) and Excel XLSX (via openpyxl)
- Strict non-destructive processing: original datasets are never modified or overwritten
"""

import io
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from config.settings import PROCESSED_DATA_DIR


@dataclass
class CleaningConfig:
    remove_duplicates: bool = True
    missing_strategy: str = "IMPUTE"  # 'IMPUTE', 'DROP', 'KEEP'
    outlier_strategy: str = "CLIP"    # 'CLIP', 'DROP', 'KEEP'
    trim_strings: bool = True
    standardize_headers: bool = False


@dataclass
class CleaningReport:
    original_rows: int
    cleaned_rows: int
    removed_rows: int
    duplicates_removed: int
    missing_handled: int
    missing_by_column: Dict[str, int]
    outliers_handled: int
    total_columns: int
    initial_quality_score: float
    final_quality_score: float
    clean_df: pd.DataFrame
    quarantined_df: pd.DataFrame
    timestamp_str: str
    clean_csv_filename: str
    clean_xlsx_filename: str
    operations_log: List[str] = field(default_factory=list)


class DataCleaningService:
    """Enterprise dataset sanitization and multi-format export service."""

    def __init__(self):
        PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    def clean(
        self,
        df: pd.DataFrame,
        config: Optional[CleaningConfig] = None,
        dataset_name: str = "dataset",
    ) -> CleaningReport:
        """Applies configured cleaning transformations to a dataframe.
        
        Preserves original dataframe by creating a deep copy.
        """
        if config is None:
            config = CleaningConfig()

        if df is None or df.empty:
            raise ValueError("Cannot clean an empty or None dataframe.")

        now = datetime.now()
        ts_str = now.strftime("%Y%m%d_%H%M%S")
        clean_csv_fname = f"dataguard_cleaned_{dataset_name.lower().replace(' ', '_')}_{ts_str}.csv"
        clean_xlsx_fname = f"dataguard_cleaned_{dataset_name.lower().replace(' ', '_')}_{ts_str}.xlsx"

        original_rows = len(df)
        total_cols = len(df.columns)
        operations: List[str] = []

        # Calculate initial quality score
        initial_score = self._compute_quick_quality_score(df)

        # Work on a clean copy
        working_df = df.copy()
        quarantined_rows = []

        # 1. Standardize Headers
        if config.standardize_headers:
            old_cols = list(working_df.columns)
            working_df.columns = [
                str(c).strip().lower().replace(" ", "_").replace("-", "_")
                for c in working_df.columns
            ]
            operations.append("Standardized column headers to snake_case format.")

        # 2. String Whitespace Trimming
        if config.trim_strings:
            str_cols = working_df.select_dtypes(include=["object", "string"]).columns
            for col in str_cols:
                working_df[col] = working_df[col].apply(
                    lambda x: x.strip() if isinstance(x, str) else x
                )
            if len(str_cols) > 0:
                operations.append(f"Trimmed leading/trailing whitespace across {len(str_cols)} text column(s).")

        # 3. Duplicate Detection & Removal
        duplicates_removed = 0
        if config.remove_duplicates:
            dup_mask = working_df.duplicated(keep="first")
            duplicates_removed = int(dup_mask.sum())
            if duplicates_removed > 0:
                quarantined_rows.append(working_df[dup_mask])
                working_df = working_df[~dup_mask].copy()
                operations.append(f"Removed {duplicates_removed} duplicate row(s) (kept first occurrence).")

        # 4. Missing Values Handling
        missing_by_column: Dict[str, int] = {}
        total_missing = int(working_df.isnull().sum().sum())
        for col in working_df.columns:
            cnt = int(working_df[col].isnull().sum())
            if cnt > 0:
                missing_by_column[str(col)] = cnt

        if config.missing_strategy == "DROP" and total_missing > 0:
            null_mask = working_df.isnull().any(axis=1)
            null_rows_dropped = int(null_mask.sum())
            quarantined_rows.append(working_df[null_mask])
            working_df = working_df[~null_mask].copy()
            operations.append(f"Dropped {null_rows_dropped} row(s) containing missing values.")

        elif config.missing_strategy == "IMPUTE" and total_missing > 0:
            imputed_count = 0
            for col in working_df.columns:
                series = working_df[col]
                null_cnt = int(series.isnull().sum())
                if null_cnt > 0:
                    if pd.api.types.is_numeric_dtype(series) and not pd.api.types.is_bool_dtype(series):
                        # Median imputation protects against skewed outliers
                        median_val = series.median()
                        if pd.notnull(median_val):
                            working_df[col] = series.fillna(median_val)
                            imputed_count += null_cnt
                    elif pd.api.types.is_datetime64_any_dtype(series):
                        working_df[col] = series.ffill().bfill()
                        imputed_count += null_cnt
                    else:
                        # Categorical / string mode imputation or 'Unknown'
                        mode_vals = series.mode()
                        fill_val = mode_vals.iloc[0] if len(mode_vals) > 0 else "Unknown"
                        working_df[col] = series.fillna(fill_val)
                        imputed_count += null_cnt
            operations.append(f"Imputed {imputed_count} missing cell(s) (numeric: median, text: mode).")

        # 5. Outlier Treatment (IQR Bounds)
        outliers_handled = 0
        if config.outlier_strategy in ["CLIP", "DROP"]:
            num_cols = [
                c for c in working_df.select_dtypes(include=[np.number]).columns
                if not pd.api.types.is_bool_dtype(working_df[c])
                and not str(c).lower().endswith("_id")
                and str(c).lower() not in ["id", "index"]
            ]

            outlier_rows_mask = pd.Series(False, index=working_df.index)

            for col in num_cols:
                col_series = working_df[col].dropna()
                if len(col_series) >= 4:
                    q1 = float(col_series.quantile(0.25))
                    q3 = float(col_series.quantile(0.75))
                    iqr = q3 - q1
                    if iqr > 0:
                        lower_bound = q1 - 1.5 * iqr
                        upper_bound = q3 + 1.5 * iqr

                        col_outliers = (col_series < lower_bound) | (col_series > upper_bound)
                        outliers_handled += int(col_outliers.sum())

                        if config.outlier_strategy == "CLIP":
                            working_df[col] = working_df[col].clip(lower=lower_bound, upper=upper_bound)
                        elif config.outlier_strategy == "DROP":
                            outlier_rows_mask = outlier_rows_mask | (working_df[col] < lower_bound) | (working_df[col] > upper_bound)

            if config.outlier_strategy == "CLIP" and outliers_handled > 0:
                operations.append(f"Clipped {outliers_handled} extreme outlier values to IQR [Q1-1.5*IQR, Q3+1.5*IQR] bounds.")
            elif config.outlier_strategy == "DROP" and outlier_rows_mask.sum() > 0:
                quarantined_rows.append(working_df[outlier_rows_mask])
                working_df = working_df[~outlier_rows_mask].copy()
                operations.append(f"Dropped {int(outlier_rows_mask.sum())} row(s) containing statistical outliers.")

        # Consolidate quarantined dead-letter rows
        if quarantined_rows:
            quarantined_df = pd.concat(quarantined_rows, ignore_index=True).drop_duplicates()
        else:
            quarantined_df = pd.DataFrame(columns=df.columns)

        cleaned_rows = len(working_df)
        removed_rows = original_rows - cleaned_rows
        final_score = self._compute_quick_quality_score(working_df)

        return CleaningReport(
            original_rows=original_rows,
            cleaned_rows=cleaned_rows,
            removed_rows=removed_rows,
            duplicates_removed=duplicates_removed,
            missing_handled=total_missing if config.missing_strategy != "KEEP" else 0,
            missing_by_column=missing_by_column,
            outliers_handled=outliers_handled,
            total_columns=total_cols,
            initial_quality_score=initial_score,
            final_quality_score=final_score,
            clean_df=working_df,
            quarantined_df=quarantined_df,
            timestamp_str=ts_str,
            clean_csv_filename=clean_csv_fname,
            clean_xlsx_filename=clean_xlsx_fname,
            operations_log=operations,
        )

    def export_csv(self, df: pd.DataFrame) -> bytes:
        """Serializes dataframe into UTF-8 encoded CSV bytes."""
        return df.to_csv(index=False).encode("utf-8")

    def export_excel(self, df: pd.DataFrame) -> bytes:
        """Serializes dataframe into formatted Excel (.xlsx) bytes using openpyxl."""
        output = io.BytesIO()
        with pd.ExcelWriter(output, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Cleaned Data")
            # Auto-adjust column widths
            worksheet = writer.sheets["Cleaned Data"]
            for col in worksheet.columns:
                max_len = 0
                col_letter = col[0].column_letter
                for cell in col:
                    try:
                        if cell.value:
                            max_len = max(max_len, len(str(cell.value)))
                    except Exception:
                        pass
                worksheet.column_dimensions[col_letter].width = min(max(max_len + 3, 10), 50)
        output.seek(0)
        return output.getvalue()

    def _compute_quick_quality_score(self, df: pd.DataFrame) -> float:
        """Calculates a baseline 0-100 quality score."""
        if df.empty:
            return 0.0

        total_cells = df.size
        null_cells = df.isnull().sum().sum()
        completeness = max(0.0, 1.0 - (null_cells / total_cells)) if total_cells > 0 else 1.0

        total_rows = len(df)
        dup_rows = df.duplicated().sum()
        uniqueness = max(0.0, 1.0 - (dup_rows / total_rows)) if total_rows > 0 else 1.0

        score = (completeness * 0.6 + uniqueness * 0.4) * 100.0
        return round(score, 1)
