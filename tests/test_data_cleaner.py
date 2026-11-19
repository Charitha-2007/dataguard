"""Automated tests for DataCleaningService.

Verifies:
- Duplicate detection and removal
- Missing value handling (median imputation for numeric, mode for categorical, row dropping)
- Statistical IQR outlier clipping and dropping
- Whitespace trimming
- Export generation (UTF-8 CSV and Excel XLSX)
- Strict immutability of the original dataframe
- Quality score improvement calculation
"""

import io
import pytest
import pandas as pd
import numpy as np

from src.services.data_cleaner import DataCleaningService, CleaningConfig


def test_duplicate_removal():
    """Validates that duplicate rows are detected and removed."""
    cleaner = DataCleaningService()
    df = pd.DataFrame({
        "id": [1, 2, 2, 3, 3, 3],
        "name": ["Alice", "Bob", "Bob", "Charlie", "Charlie", "Charlie"],
        "score": [10.0, 20.0, 20.0, 30.0, 30.0, 30.0],
    })

    report = cleaner.clean(df, CleaningConfig(remove_duplicates=True))
    assert report.original_rows == 6
    assert report.cleaned_rows == 3
    assert report.duplicates_removed == 3
    assert len(report.clean_df) == 3
    assert report.clean_df["id"].tolist() == [1, 2, 3]


def test_missing_values_smart_imputation():
    """Validates that missing values are imputed using median for numeric and mode for text."""
    cleaner = DataCleaningService()
    df = pd.DataFrame({
        "user_id": [1, 2, 3, 4, 5],
        "salary": [1000.0, 2000.0, np.nan, 4000.0, 5000.0],  # Median is 3000.0
        "city": ["New York", "Chicago", "New York", np.nan, "New York"],  # Mode is New York
    })

    report = cleaner.clean(df, CleaningConfig(missing_strategy="IMPUTE"))
    assert report.cleaned_rows == 5
    assert report.missing_handled == 2
    assert report.clean_df["salary"].isnull().sum() == 0
    assert report.clean_df["salary"].iloc[2] == 3000.0
    assert report.clean_df["city"].iloc[3] == "New York"
    assert report.final_quality_score > report.initial_quality_score


def test_missing_values_drop_rows():
    """Validates that missing strategy 'DROP' removes rows with nulls."""
    cleaner = DataCleaningService()
    df = pd.DataFrame({
        "id": [1, 2, 3, 4],
        "val": [10.0, np.nan, 30.0, 40.0],
    })

    report = cleaner.clean(df, CleaningConfig(missing_strategy="DROP"))
    assert report.original_rows == 4
    assert report.cleaned_rows == 3
    assert report.removed_rows == 1
    assert 2 not in report.clean_df["id"].values


def test_outlier_clipping_iqr():
    """Validates that extreme statistical outliers are clipped to IQR bounds."""
    cleaner = DataCleaningService()
    # 20 points centered around 50, with one massive 1000.0 anomaly
    values = [45.0, 48.0, 50.0, 52.0, 55.0] * 4 + [1000.0]
    df = pd.DataFrame({"metric": values})

    report = cleaner.clean(df, CleaningConfig(remove_duplicates=False, outlier_strategy="CLIP"))
    assert report.outliers_handled >= 1
    assert report.clean_df["metric"].max() < 1000.0
    assert len(report.clean_df) == len(df)  # Rows preserved, value clipped


def test_whitespace_trimming():
    """Validates that leading and trailing whitespace is stripped from text columns."""
    cleaner = DataCleaningService()
    df = pd.DataFrame({
        "code": ["  ABC  ", "XYZ  ", "   123"],
        "num": [1, 2, 3],
    })

    report = cleaner.clean(df, CleaningConfig(trim_strings=True))
    assert report.clean_df["code"].tolist() == ["ABC", "XYZ", "123"]


def test_original_dataframe_immutability():
    """Validates that the source dataframe is strictly unchanged by cleaning operations."""
    cleaner = DataCleaningService()
    df_orig = pd.DataFrame({
        "id": [1, 1, 2],
        "name": [" A ", " A ", " B "],
        "val": [10.0, 10.0, np.nan],
    })
    df_copy = df_orig.copy(deep=True)

    cleaner.clean(df_orig, CleaningConfig(remove_duplicates=True, missing_strategy="DROP"))

    # Original dataframe must be strictly identical
    pd.testing.assert_frame_equal(df_orig, df_copy)


def test_export_to_csv_and_excel():
    """Validates serialization to valid CSV and XLSX binary byte streams."""
    cleaner = DataCleaningService()
    df = pd.DataFrame({
        "product_id": [101, 102, 103],
        "name": ["Laptop", "Mouse", "Keyboard"],
        "price": [999.99, 29.99, 79.99],
    })

    # CSV Export
    csv_bytes = cleaner.export_csv(df)
    assert isinstance(csv_bytes, bytes)
    assert len(csv_bytes) > 0
    df_reloaded_csv = pd.read_csv(io.BytesIO(csv_bytes))
    assert len(df_reloaded_csv) == 3
    assert "product_id" in df_reloaded_csv.columns

    # Excel Export
    xlsx_bytes = cleaner.export_excel(df)
    assert isinstance(xlsx_bytes, bytes)
    assert len(xlsx_bytes) > 0
    df_reloaded_xlsx = pd.read_excel(io.BytesIO(xlsx_bytes), engine="openpyxl")
    assert len(df_reloaded_xlsx) == 3
    assert "Laptop" in df_reloaded_xlsx["name"].values
