"""Dataset Service for DataGuard Platform.

Handles end-to-end dataset lifecycle:
- Multi-format ingestion (.csv, .xlsx, .xls, .json) with error handling & validation
- Dynamic data profiling & quality metrics calculation (missing, duplicates, outliers, types)
- Dataset catalog persistence, replacement, and safe deletion
- 5-stage observable pipeline execution on uploaded datasets with automated RCA & incident gating
"""

import io
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd

from config.settings import (
    DEFAULT_DUPLICATE_THRESHOLD_PCT,
    DEFAULT_NULL_THRESHOLD_PCT,
    PROCESSED_DATA_DIR,
    UPLOAD_DATA_DIR,
)
from src.core.drift_detector import DriftAnomalyDetector
from src.core.impact_analyzer import DependencyImpactAnalyzer
from src.core.quality_engine import CheckDetail, QualityReport
from src.core.rca_engine import RootCauseAnalysisEngine
from src.database.models import UploadedDataset, Pipeline, PipelineRun
from src.database.repository import DataGuardRepository
from src.recovery.approval_workflow import ApprovalWorkflowManager
from src.recovery.recommendation import RecoveryRecommendationEngine
from src.services.incident_manager import IncidentManager


class DatasetService:
    """Enterprise dataset management and pipeline integration service."""

    def __init__(
        self,
        repo: Optional[DataGuardRepository] = None,
        incident_manager: Optional[IncidentManager] = None,
        rca_engine: Optional[RootCauseAnalysisEngine] = None,
        drift_detector: Optional[DriftAnomalyDetector] = None,
        recommender: Optional[RecoveryRecommendationEngine] = None,
        workflow: Optional[ApprovalWorkflowManager] = None,
    ):
        self.repo = repo or DataGuardRepository()
        self.incident_manager = incident_manager
        self.rca_engine = rca_engine or RootCauseAnalysisEngine()
        self.drift_detector = drift_detector or DriftAnomalyDetector()
        self.recommender = recommender or RecoveryRecommendationEngine(repo=self.repo)
        self.workflow = workflow or ApprovalWorkflowManager(repo=self.repo)

    # =========================================================================
    # 1. FILE PARSING & VALIDATION
    # =========================================================================

    def parse_file(
        self,
        file_source: Union[bytes, io.BytesIO, str, Path],
        filename: str,
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """Parses an uploaded file into a pandas DataFrame with validation.

        Supports CSV (.csv), Excel (.xlsx, .xls), and JSON (.json).
        Raises ValueError with clear, actionable message if invalid.
        """
        if not filename:
            raise ValueError("Filename is required for parsing.")

        ext = Path(filename).suffix.lower()
        if ext not in [".csv", ".xlsx", ".xls", ".json"]:
            raise ValueError(
                f"Unsupported file format '{ext}'. Supported formats: .csv, .xlsx, .xls, .json"
            )

        # Determine file size
        file_size_bytes = 0
        file_buffer: Union[io.BytesIO, str]
        if isinstance(file_source, bytes):
            file_size_bytes = len(file_source)
            if file_size_bytes == 0:
                raise ValueError("Uploaded file is empty (0 bytes).")
            file_buffer = io.BytesIO(file_source)
        elif isinstance(file_source, io.BytesIO):
            file_source.seek(0, io.SEEK_END)
            file_size_bytes = file_source.tell()
            file_source.seek(0)
            if file_size_bytes == 0:
                raise ValueError("Uploaded file is empty (0 bytes).")
            file_buffer = file_source
        elif isinstance(file_source, (str, Path)):
            path_obj = Path(file_source)
            if not path_obj.exists():
                raise ValueError(f"File not found on disk: {file_source}")
            file_size_bytes = path_obj.stat().st_size
            if file_size_bytes == 0:
                raise ValueError("Uploaded file is empty (0 bytes).")
            file_buffer = str(path_obj)
        else:
            # File-like object (e.g. Streamlit UploadedFile)
            content = file_source.read()
            file_size_bytes = len(content)
            if file_size_bytes == 0:
                raise ValueError("Uploaded file is empty (0 bytes).")
            file_buffer = io.BytesIO(content)

        # Parse based on extension
        df: pd.DataFrame
        try:
            if ext == ".csv":
                df = self._read_csv_with_fallback(file_buffer)
            elif ext in [".xlsx", ".xls"]:
                df = self._read_excel_safely(file_buffer)
            elif ext == ".json":
                df = self._read_json_safely(file_buffer)
            else:
                raise ValueError(f"Unsupported extension: {ext}")
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Failed to parse {filename}: {str(e)}")

        if df.empty:
            raise ValueError(f"File '{filename}' contains no rows or data records.")

        # Clean column names (strip whitespace, ensure string)
        df.columns = [str(c).strip() for c in df.columns]

        meta = {
            "filename": filename,
            "file_type": ext.replace(".", ""),
            "file_size_bytes": file_size_bytes,
            "row_count": len(df),
            "column_count": len(df.columns),
            "columns": list(df.columns),
            "memory_mb": round(df.memory_usage(deep=True).sum() / (1024 * 1024), 2),
        }
        return df, meta

    def _read_csv_with_fallback(self, buffer: Union[io.BytesIO, str]) -> pd.DataFrame:
        """Reads CSV with encoding fallback (utf-8, latin-1, cp1252) and delimiter detection.
        
        Validates against binary file headers and null bytes to prevent binary masquerading.
        """
        # Inspect header bytes to reject binary files disguised as CSV
        sample = b""
        if isinstance(buffer, io.BytesIO):
            buffer.seek(0)
            sample = buffer.read(1024)
            buffer.seek(0)
        elif isinstance(buffer, str) and Path(buffer).exists():
            with open(buffer, "rb") as f:
                sample = f.read(1024)

        KNOWN_BINARY_MAGIC = [
            b"\x89PNG",        # PNG image
            b"\xff\xd8\xff",    # JPEG image
            b"%PDF",            # PDF document
            b"PK\x03\x04",      # ZIP archive / docx / xlsx
            b"GIF87a", b"GIF89a",  # GIF image
            b"\x7fELF",         # Linux executable/shared library
            b"MZ",              # Windows executable / DLL
        ]
        if any(sample.startswith(magic) for magic in KNOWN_BINARY_MAGIC) or b"\x00" in sample:
            raise ValueError("The provided file appears to be a binary file, not a valid plain text CSV.")

        encodings = ["utf-8", "latin-1", "cp1252"]
        last_error = None

        for enc in encodings:
            try:
                if isinstance(buffer, io.BytesIO):
                    buffer.seek(0)
                # First try with default comma
                df = pd.read_csv(buffer, encoding=enc)
                # If only 1 column and contains commas/semicolons/tabs, try auto delimiter
                if len(df.columns) == 1 and len(df) > 0:
                    first_col = df.columns[0]
                    if ";" in first_col or "\t" in first_col:
                        if isinstance(buffer, io.BytesIO):
                            buffer.seek(0)
                        df = pd.read_csv(buffer, encoding=enc, sep=None, engine="python")
                return df
            except Exception as e:
                last_error = e

        raise ValueError(f"Could not parse CSV with common encodings. Last error: {last_error}")

    def _read_excel_safely(self, buffer: Union[io.BytesIO, str]) -> pd.DataFrame:
        """Reads Excel file using openpyxl engine with explicit error handling."""
        try:
            if isinstance(buffer, io.BytesIO):
                buffer.seek(0)
            return pd.read_excel(buffer, engine="openpyxl")
        except ImportError:
            raise ValueError("openpyxl package is required for Excel parsing. Run: pip install openpyxl")
        except Exception as e:
            raise ValueError(f"Corrupted or invalid Excel spreadsheet: {e}")

    def _read_json_safely(self, buffer: Union[io.BytesIO, str]) -> pd.DataFrame:
        """Reads JSON files supporting list of records, dict of lists, or lines."""
        try:
            if isinstance(buffer, io.BytesIO):
                buffer.seek(0)
                raw_text = buffer.read().decode("utf-8")
            else:
                with open(buffer, "r", encoding="utf-8") as f:
                    raw_text = f.read()

            parsed = json.loads(raw_text)
            if isinstance(parsed, list):
                return pd.DataFrame(parsed)
            elif isinstance(parsed, dict):
                # Try records or orient='columns'
                try:
                    return pd.DataFrame(parsed)
                except Exception:
                    # If nested under a key like 'data', 'records', 'items'
                    for key in ["data", "records", "items", "results"]:
                        if key in parsed and isinstance(parsed[key], list):
                            return pd.DataFrame(parsed[key])
                    return pd.json_normalize(parsed)
            else:
                raise ValueError("JSON must be an array of records or a dictionary object.")
        except Exception as e:
            raise ValueError(f"Invalid JSON data: {e}")

    # =========================================================================
    # 2. DYNAMIC QUALITY PROFILING & ANOMALY DETECTION
    # =========================================================================

    def profile_dataset(
        self,
        df: pd.DataFrame,
        dataset_name: str = "dataset",
    ) -> Dict[str, Any]:
        """Performs comprehensive data profiling and quality metrics calculation.

        Returns:
            - Missing values (total, %, per column)
            - Duplicate records (total, %)
            - Column types and summary statistics
            - Outlier counts per numerical column (IQR method)
            - Quality Health Score (0-100%) and Grade (A-F)
            - Structured CheckDetail items
        """
        total_rows = len(df)
        total_cols = len(df.columns)
        total_cells = total_rows * total_cols if total_rows > 0 else 1

        # Missing values
        null_counts = df.isna().sum().to_dict()
        missing_total = int(sum(null_counts.values()))
        missing_pct = round((missing_total / total_cells) * 100, 2) if total_cells > 0 else 0.0

        missing_by_col = {}
        for col, cnt in null_counts.items():
            pct = round((cnt / total_rows) * 100, 2) if total_rows > 0 else 0.0
            missing_by_col[col] = {"count": int(cnt), "percentage": pct}

        # Duplicates
        duplicate_rows = int(df.duplicated().sum())
        duplicate_pct = round((duplicate_rows / total_rows) * 100, 2) if total_rows > 0 else 0.0

        # Column Profiling
        column_profiles = {}
        numeric_cols = []
        categorical_cols = []
        total_outliers = 0

        checks: List[CheckDetail] = []
        corrupted_indices = set()

        # Add duplicate check
        if duplicate_pct > DEFAULT_DUPLICATE_THRESHOLD_PCT:
            checks.append(
                CheckDetail(
                    check_name="duplicate_records_rate",
                    status="WARNING" if duplicate_pct < 10 else "FAILED",
                    category="UNIQUENESS",
                    message=f"High duplicate rate: {duplicate_rows} duplicate rows ({duplicate_pct}%).",
                    metric_value=duplicate_pct,
                    threshold=DEFAULT_DUPLICATE_THRESHOLD_PCT,
                    affected_rows_count=duplicate_rows,
                )
            )
            # Find duplicate indices
            dup_idx = df[df.duplicated()].index.tolist()
            corrupted_indices.update(dup_idx)
        else:
            checks.append(
                CheckDetail(
                    check_name="duplicate_records_rate",
                    status="PASSED",
                    category="UNIQUENESS",
                    message=f"Duplicate rate acceptable: {duplicate_pct}%.",
                    metric_value=duplicate_pct,
                    threshold=DEFAULT_DUPLICATE_THRESHOLD_PCT,
                    affected_rows_count=duplicate_rows,
                )
            )

        for col in df.columns:
            series = df[col]
            dtype_str = str(series.dtype)
            null_count = int(null_counts.get(col, 0))
            col_null_pct = round((null_count / total_rows) * 100, 2) if total_rows > 0 else 0.0
            unique_count = int(series.nunique(dropna=True))

            # Check for null spike
            if col_null_pct > DEFAULT_NULL_THRESHOLD_PCT:
                checks.append(
                    CheckDetail(
                        check_name=f"null_rate_{col}",
                        status="FAILED",
                        category="COMPLETENESS",
                        message=f"Null spike in column '{col}': {col_null_pct}% missing.",
                        metric_value=col_null_pct,
                        threshold=DEFAULT_NULL_THRESHOLD_PCT,
                        affected_rows_count=null_count,
                    )
                )
                null_idx = df[series.isna()].index.tolist()
                corrupted_indices.update(null_idx)
            else:
                checks.append(
                    CheckDetail(
                        check_name=f"null_rate_{col}",
                        status="PASSED",
                        category="COMPLETENESS",
                        message=f"Column '{col}' null rate acceptable: {col_null_pct}%.",
                        metric_value=col_null_pct,
                        threshold=DEFAULT_NULL_THRESHOLD_PCT,
                        affected_rows_count=null_count,
                    )
                )

            # Profiling details
            col_meta: Dict[str, Any] = {
                "dtype": dtype_str,
                "null_count": null_count,
                "null_pct": col_null_pct,
                "unique_count": unique_count,
                "outliers_count": 0,
            }

            # Numeric columns profiling (exclude booleans from quantile calculations)
            if pd.api.types.is_numeric_dtype(series) and not pd.api.types.is_bool_dtype(series):
                numeric_cols.append(col)
                clean_num = series.dropna()
                if len(clean_num) > 0:
                    q1 = float(clean_num.quantile(0.25))
                    q3 = float(clean_num.quantile(0.75))
                    iqr = q3 - q1
                    lower_bound = q1 - 1.5 * iqr
                    upper_bound = q3 + 1.5 * iqr
                    outliers_mask = (clean_num < lower_bound) | (clean_num > upper_bound)
                    col_outliers = int(outliers_mask.sum())
                    total_outliers += col_outliers

                    col_meta.update({
                        "min": round(float(clean_num.min()), 2),
                        "max": round(float(clean_num.max()), 2),
                        "mean": round(float(clean_num.mean()), 2),
                        "median": round(float(clean_num.median()), 2),
                        "std": round(float(clean_num.std()), 2) if len(clean_num) > 1 else 0.0,
                        "iqr_lower": round(lower_bound, 2),
                        "iqr_upper": round(upper_bound, 2),
                        "outliers_count": col_outliers,
                    })

                    if col_outliers > 0:
                        outlier_pct = round((col_outliers / total_rows) * 100, 2)
                        checks.append(
                            CheckDetail(
                                check_name=f"outlier_bounds_{col}",
                                status="WARNING" if outlier_pct < 5 else "FAILED",
                                category="VALIDITY",
                                message=f"Column '{col}' contains {col_outliers} statistical outliers ({outlier_pct}%).",
                                metric_value=outlier_pct,
                                threshold=5.0,
                                affected_rows_count=col_outliers,
                            )
                        )
            else:
                categorical_cols.append(col)
                # Frequent values
                top_vals = series.value_counts(dropna=True).head(5).to_dict()
                col_meta["top_values"] = {str(k): int(v) for k, v in top_vals.items()}

            # Constant column check
            if unique_count <= 1 and total_rows > 1:
                checks.append(
                    CheckDetail(
                        check_name=f"constant_column_{col}",
                        status="WARNING",
                        category="SCHEMA",
                        message=f"Column '{col}' has zero variance (constant value across all rows).",
                        affected_rows_count=total_rows,
                    )
                )

            column_profiles[col] = col_meta

        # =====================================================================
        # Dynamic Quality Score Calculation
        # =====================================================================
        # Completeness: 40 points
        completeness_score = max(0.0, 40.0 - (missing_pct * 1.5))
        # Uniqueness: 30 points
        uniqueness_score = max(0.0, 30.0 - (duplicate_pct * 2.0))
        # Validity & Outliers: 30 points
        outlier_pct_overall = (total_outliers / total_cells) * 100 if total_cells > 0 else 0.0
        validity_score = max(0.0, 30.0 - (outlier_pct_overall * 3.0))

        quality_score = round(completeness_score + uniqueness_score + validity_score, 1)
        quality_score = max(0.0, min(100.0, quality_score))

        # Health Grade
        if quality_score >= 90:
            health_grade = "A"
        elif quality_score >= 80:
            health_grade = "B"
        elif quality_score >= 70:
            health_grade = "C"
        elif quality_score >= 60:
            health_grade = "D"
        else:
            health_grade = "F"

        passed_checks = sum(1 for c in checks if c.status == "PASSED")
        failed_checks = sum(1 for c in checks if c.status == "FAILED")
        warning_checks = sum(1 for c in checks if c.status == "WARNING")

        checks_summary = [
            {
                "check_name": c.check_name,
                "status": c.status,
                "category": c.category,
                "message": c.message,
                "metric_value": c.metric_value,
                "threshold": c.threshold,
                "affected_rows_count": c.affected_rows_count,
            }
            for c in checks
        ]

        return {
            "dataset_name": dataset_name,
            "quality_score": quality_score,
            "health_grade": health_grade,
            "is_healthy": quality_score >= 80.0,
            "total_rows": total_rows,
            "total_columns": total_cols,
            "total_cells": total_cells,
            "missing_total": missing_total,
            "missing_pct": missing_pct,
            "missing_by_column": missing_by_col,
            "duplicate_total": duplicate_rows,
            "duplicate_pct": duplicate_pct,
            "numeric_columns": numeric_cols,
            "categorical_columns": categorical_cols,
            "column_profiles": column_profiles,
            "total_outliers": total_outliers,
            "corrupted_rows_count": len(corrupted_indices),
            "corrupted_indices": list(sorted(corrupted_indices)),
            "passed_checks_count": passed_checks,
            "failed_checks_count": failed_checks,
            "warning_checks_count": warning_checks,
            "checks": checks,
            "checks_summary": checks_summary,
        }

    # =========================================================================
    # 3. DATASET REPOSITORY & STORAGE MANAGEMENT
    # =========================================================================

    def save_dataset(
        self,
        name: str,
        filename: str,
        df: pd.DataFrame,
        raw_bytes: bytes,
        actor: str = "admin",
    ) -> UploadedDataset:
        """Persists uploaded dataset to disk, computes initial profiling, and saves DB record."""
        # Clean dataset name
        safe_name = name.strip() if name and name.strip() else Path(filename).stem
        ext = Path(filename).suffix.lower()

        dataset_id = f"DS-{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.urandom(2).hex().upper()}"
        file_path = UPLOAD_DATA_DIR / f"{dataset_id}_{filename}"

        # Write raw bytes to disk
        with open(file_path, "wb") as f:
            f.write(raw_bytes)

        # Profile dataset
        profile = self.profile_dataset(df, dataset_name=safe_name)

        dataset = UploadedDataset(
            id=dataset_id,
            name=safe_name,
            filename=filename,
            file_type=ext.replace(".", ""),
            file_size_bytes=len(raw_bytes),
            row_count=len(df),
            column_count=len(df.columns),
            columns_json=json.dumps(list(df.columns)),
            quality_score=profile["quality_score"],
            missing_count=profile["missing_total"],
            duplicate_count=profile["duplicate_total"],
            file_path=str(file_path),
            uploaded_by=actor,
            status="UPLOADED",
        )

        self.repo.create_dataset(dataset)

        # Audit log
        self.repo.log_audit_event(
            actor=actor,
            action="DATASET_UPLOADED",
            entity_type="DATASET",
            entity_id=dataset_id,
            details={
                "name": safe_name,
                "filename": filename,
                "file_size_bytes": len(raw_bytes),
                "row_count": len(df),
                "quality_score": profile["quality_score"],
            },
        )

        return dataset

    def replace_dataset(
        self,
        dataset_id: str,
        new_name: str,
        new_filename: str,
        df: pd.DataFrame,
        raw_bytes: bytes,
        actor: str = "admin",
    ) -> UploadedDataset:
        """Replaces an existing dataset's physical file and updates its metadata."""
        existing = self.repo.get_dataset(dataset_id)
        if not existing:
            raise ValueError(f"Dataset #{dataset_id} does not exist.")

        # Remove old physical file if exists
        old_path = Path(existing["file_path"])
        if old_path.exists():
            try:
                old_path.unlink()
            except Exception:
                pass

        ext = Path(new_filename).suffix.lower()
        new_path = UPLOAD_DATA_DIR / f"{dataset_id}_{new_filename}"

        with open(new_path, "wb") as f:
            f.write(raw_bytes)

        profile = self.profile_dataset(df, dataset_name=new_name)

        self.repo.update_dataset_file(
            dataset_id=dataset_id,
            name=new_name,
            filename=new_filename,
            file_type=ext.replace(".", ""),
            file_size_bytes=len(raw_bytes),
            row_count=len(df),
            column_count=len(df.columns),
            columns_json=json.dumps(list(df.columns)),
            file_path=str(new_path),
            quality_score=profile["quality_score"],
            missing_count=profile["missing_total"],
            duplicate_count=profile["duplicate_total"],
            status="UPLOADED",
        )

        self.repo.log_audit_event(
            actor=actor,
            action="DATASET_REPLACED",
            entity_type="DATASET",
            entity_id=dataset_id,
            details={
                "name": new_name,
                "new_filename": new_filename,
                "row_count": len(df),
                "quality_score": profile["quality_score"],
            },
        )

        updated = self.repo.get_dataset(dataset_id)
        return UploadedDataset(**updated)

    def delete_dataset(self, dataset_id: str, actor: str = "admin") -> bool:
        """Safely removes a dataset's file and deletes its database entry."""
        existing = self.repo.get_dataset(dataset_id)
        if not existing:
            return False

        # Remove physical file
        path = Path(existing["file_path"])
        if path.exists():
            try:
                path.unlink()
            except Exception:
                pass

        success = self.repo.delete_dataset(dataset_id)
        if success:
            self.repo.log_audit_event(
                actor=actor,
                action="DATASET_DELETED",
                entity_type="DATASET",
                entity_id=dataset_id,
                details={"name": existing["name"], "filename": existing["filename"]},
            )
        return success

    def load_dataset_df(self, dataset_id: str) -> Optional[pd.DataFrame]:
        """Loads the parsed DataFrame for an existing dataset."""
        record = self.repo.get_dataset(dataset_id)
        if not record or not record.get("file_path"):
            return None

        path = Path(record["file_path"])
        if not path.exists():
            return None

        df, _ = self.parse_file(str(path), record["filename"])
        return df

    def get_all_datasets(self) -> List[Dict[str, Any]]:
        """Retrieves all uploaded datasets."""
        return self.repo.get_all_datasets()

    # =========================================================================
    # 4. OBSERVABLE PIPELINE INTEGRATION
    # =========================================================================

    def execute_pipeline_on_dataset(
        self,
        dataset_id: str,
        actor: str = "admin",
    ) -> Dict[str, Any]:
        """Executes a 5-stage observable pipeline on an uploaded dataset.

        Stages:
            1. INGESTION: File reading, schema validation, latency measurement
            2. DATA_QUALITY: Deep profiling, null check, duplicate check, contract validation
            3. DRIFT_ANOMALY: Statistical distribution evaluation on numerical columns
            4. RCA_DIAGNOSIS: Root cause analysis if quality score < 80% or severe issues
            5. REMEDIATION_OUTPUT: Output routing (clean batch vs quarantine dead-letter) & incident gate
        """
        start_time = time.time()
        record = self.repo.get_dataset(dataset_id)
        if not record:
            raise ValueError(f"Dataset #{dataset_id} not found.")

        stages_log: List[Dict[str, Any]] = []

        # -------------------------------------------------------------
        # STAGE 1: INGESTION
        # -------------------------------------------------------------
        stage1_start = time.time()
        df = self.load_dataset_df(dataset_id)
        if df is None:
            raise ValueError(f"Could not load physical data file for dataset {dataset_id}")

        stage1_duration = round(time.time() - stage1_start, 3)
        stages_log.append({
            "stage": "1. Ingestion & Pre-Validation",
            "status": "PASSED",
            "duration_seconds": stage1_duration,
            "details": f"Loaded {len(df)} rows, {len(df.columns)} columns from {record['filename']} ({stage1_duration}s).",
        })

        # -------------------------------------------------------------
        # STAGE 2: DATA QUALITY & CONTRACT VALIDATION
        # -------------------------------------------------------------
        stage2_start = time.time()
        profile = self.profile_dataset(df, dataset_name=record["name"])
        stage2_duration = round(time.time() - stage2_start, 3)

        quality_report = QualityReport(
            pipeline_id=f"pipeline_{dataset_id}",
            is_valid=profile["is_healthy"],
            quality_score=profile["quality_score"],
            total_rows=profile["total_rows"],
            passed_count=profile["passed_checks_count"],
            failed_count=profile["failed_checks_count"],
            corrupted_indices=profile["corrupted_indices"],
            checks=profile["checks"],
        )

        stage2_status = "PASSED" if profile["is_healthy"] else "FAILED"
        stages_log.append({
            "stage": "2. Data Quality & Contract Checks",
            "status": stage2_status,
            "duration_seconds": stage2_duration,
            "details": f"Quality Score: {profile['quality_score']}% (Grade {profile['health_grade']}). Missing: {profile['missing_total']}, Duplicates: {profile['duplicate_total']}.",
        })

        # -------------------------------------------------------------
        # STAGE 3: DRIFT & OUTLIER DETECTION
        # -------------------------------------------------------------
        stage3_start = time.time()
        drift_report = None
        # Select numeric features for drift analysis, excluding identifier/primary-key columns
        numeric_cols = [
            c for c in profile["numeric_columns"]
            if not (c.lower() == "id" or c.lower().endswith("_id") or c.lower().startswith("id_") or c.lower() == "index")
        ]

        # Only run statistical distribution drift when sample size is sufficient (>= 150 rows)
        # Small sample sizes (< 150 rows) produce erratic quantile binning noise in PSI
        if len(numeric_cols) > 0 and len(df) >= 150:
            # Split dataset into half (1st half as baseline reference, 2nd half as incoming batch)
            split_idx = len(df) // 2
            ref_slice = df.iloc[:split_idx]
            cur_slice = df.iloc[split_idx:]
            try:
                drift_report = self.drift_detector.evaluate(
                    pipeline_id=f"pipeline_{dataset_id}",
                    reference_df=ref_slice,
                    current_df=cur_slice,
                    numeric_columns=numeric_cols[:3],  # evaluate up to top 3 numeric features
                )
            except Exception:
                drift_report = None

        stage3_duration = round(time.time() - stage3_start, 3)
        drift_summary = "No significant drift detected"
        has_drift = False
        if drift_report and drift_report.has_drift_or_anomaly:
            drifting_cols = [
                col for col, r in drift_report.column_drifts.items() if r.is_drift_detected
            ]
            has_drift = len(drifting_cols) > 0
            if has_drift:
                drift_summary = f"Drift detected in {len(drifting_cols)} features: {', '.join(drifting_cols)}"
            elif drift_report.multivariate_anomaly.is_anomaly_detected:
                drift_summary = f"ML Anomaly detected: {drift_report.multivariate_anomaly.anomaly_count} rows ({drift_report.multivariate_anomaly.anomaly_percentage}%)"

        stages_log.append({
            "stage": "3. Statistical Drift & ML Anomaly Detection",
            "status": "WARNING" if has_drift else "PASSED",
            "duration_seconds": stage3_duration,
            "details": f"{drift_summary} ({stage3_duration}s). Outliers detected: {profile['total_outliers']}.",
        })

        # -------------------------------------------------------------
        # STAGE 4: ROOT CAUSE ANALYSIS & DIAGNOSIS
        # -------------------------------------------------------------
        stage4_start = time.time()
        total_duration = round(time.time() - start_time, 3)

        diagnosis = self.rca_engine.diagnose(
            pipeline_id=f"dataset_{dataset_id}",
            sla_seconds=300,
            duration_seconds=total_duration,
            row_count=len(df),
            quality_report=quality_report,
            drift_report=drift_report,
        )

        stage4_duration = round(time.time() - stage4_start, 3)
        if diagnosis:
            stages_log.append({
                "stage": "4. Root Cause Analysis (RCA)",
                "status": "FAILED",
                "duration_seconds": stage4_duration,
                "details": f"Diagnosed: {diagnosis.incident_type} (Severity: {diagnosis.severity}). Cause: {diagnosis.root_cause_summary}",
            })
        else:
            stages_log.append({
                "stage": "4. Root Cause Analysis (RCA)",
                "status": "PASSED",
                "duration_seconds": stage4_duration,
                "details": "All diagnostic gates passed cleanly. Zero root-cause anomalies.",
            })

        # -------------------------------------------------------------
        # STAGE 5: REMEDIATION & OUTPUT ROUTING
        # -------------------------------------------------------------
        stage5_start = time.time()
        run_id = f"RUN-DS-{datetime.now().strftime('%Y%m%d%H%M%S')}-{os.urandom(2).hex().upper()}"
        run_status = "FAILED" if diagnosis else "SUCCESS"
        incident_code = None

        clean_path = None
        quarantine_path = None

        # Check or register dynamic pipeline entry in database
        existing_pipe = self.repo.get_pipeline(f"dataset_{dataset_id}")
        if not existing_pipe:
            self.repo.create_pipeline(
                Pipeline(
                    id=f"dataset_{dataset_id}",
                    name=f"Dataset: {record['name']}",
                    description=f"User uploaded ingestion pipeline for {record['filename']}",
                    source_type=record["file_type"],
                    schedule_cron="manual",
                    sla_seconds=300,
                    owner_email=f"{actor}@dataguard.local",
                    is_active=1,
                )
            )

        # Pre-record pipeline run with RUNNING status (satisfies Foreign Key constraints)
        run_obj = PipelineRun(
            run_id=run_id,
            pipeline_id=f"dataset_{dataset_id}",
            status="RUNNING",
            started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            raw_data_path=record["file_path"],
        )
        self.repo.create_run(run_obj)

        if run_status == "SUCCESS":
            # Output clean data
            clean_file = PROCESSED_DATA_DIR / f"clean_{dataset_id}.csv"
            df.to_csv(clean_file, index=False)
            clean_path = str(clean_file)
            stages_log.append({
                "stage": "5. Remediation & Output Routing",
                "status": "PASSED",
                "duration_seconds": round(time.time() - stage5_start, 3),
                "details": f"Clean dataset persisted to {clean_file.name}. Ready for warehouse consumption.",
            })
        else:
            # Quarantine corrupted rows
            corrupted_idx = profile["corrupted_indices"]
            if corrupted_idx:
                quarantine_df = df.iloc[corrupted_idx]
                quar_file = PROCESSED_DATA_DIR / f"quarantine_{dataset_id}.csv"
                quarantine_df.to_csv(quar_file, index=False)
                quarantine_path = str(quar_file)

            # Trigger incident if incident_manager provided
            if self.incident_manager and diagnosis:
                impact_report = DependencyImpactAnalyzer(repo=self.repo).analyze_impact(f"dataset_{dataset_id}")
                incident = self.incident_manager.create_incident(
                    run_id=run_id,
                    pipeline_id=f"dataset_{dataset_id}",
                    diagnosis=diagnosis,
                    impact_report=impact_report,
                )
                incident_code = incident.incident_code

                # Generate recovery recommendation plan
                plan = self.recommender.generate_plan(
                    incident_type=diagnosis.incident_type,
                    pipeline_id=f"dataset_{dataset_id}",
                    corrupted_indices=profile["corrupted_indices"],
                    raw_data_path=record["file_path"],
                )
                self.workflow.submit_recovery_request(
                    incident_code=incident_code,
                    pipeline_id=f"dataset_{dataset_id}",
                    plan=plan,
                )

            stages_log.append({
                "stage": "5. Remediation & Output Routing",
                "status": "FAILED",
                "duration_seconds": round(time.time() - stage5_start, 3),
                "details": f"Quarantined {len(profile['corrupted_indices'])} invalid rows. Incident {incident_code or 'ticket'} created.",
            })

        # Update pipeline run to final status
        total_time = round(time.time() - start_time, 3)
        serializable_profile = {k: v for k, v in profile.items() if k != "checks"}
        serializable_profile["checks"] = profile.get("checks_summary", [])
        self.repo.update_run(
            run_id=run_id,
            status=run_status,
            completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            duration_seconds=total_time,
            row_count=len(df),
            error_message=diagnosis.root_cause_summary if diagnosis else None,
            metrics_json=serializable_profile,
            processed_data_path=clean_path or quarantine_path,
        )

        # Update dataset status & metrics
        self.repo.update_dataset_metrics(
            dataset_id=dataset_id,
            quality_score=profile["quality_score"],
            missing_count=profile["missing_total"],
            duplicate_count=profile["duplicate_total"],
            status="PROCESSED" if run_status == "SUCCESS" else "FAILED",
        )

        # Log audit trail
        self.repo.log_audit_event(
            actor=actor,
            action="DATASET_PIPELINE_EXECUTED",
            entity_type="PIPELINE_RUN",
            entity_id=run_id,
            details={
                "dataset_id": dataset_id,
                "status": run_status,
                "quality_score": profile["quality_score"],
                "total_rows": len(df),
                "duration_seconds": total_time,
                "incident_code": incident_code,
            },
        )

        return {
            "dataset_id": dataset_id,
            "dataset_name": record["name"],
            "run_id": run_id,
            "status": run_status,
            "quality_score": profile["quality_score"],
            "health_grade": profile["health_grade"],
            "total_rows": len(df),
            "total_duration_seconds": total_time,
            "stages": stages_log,
            "incident_code": incident_code,
            "profile": profile,
            "diagnosis": diagnosis,
            "clean_path": clean_path,
            "quarantine_path": quarantine_path,
        }
