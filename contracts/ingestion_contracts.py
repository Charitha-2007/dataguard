"""Ingestion Service Contract - Owned by Member 2 (Data Engineering & Backend)."""

from typing import Protocol, Dict, Any, Optional, Tuple
import pandas as pd


class IIngestionService(Protocol):
    """Contract for dataset ingestion, profiling, and pipeline execution."""

    def parse_file(
        self,
        file_bytes: bytes,
        filename: str,
    ) -> Tuple[Optional[pd.DataFrame], Optional[str]]:
        """Parses file bytes into DataFrame across CSV, JSON, and Excel formats."""
        ...

    def profile_dataset(
        self,
        df: pd.DataFrame,
    ) -> Dict[str, Any]:
        """Generates statistical profile (nulls, duplicates, column schemas, memory)."""
        ...

    def save_dataset(
        self,
        name: str,
        raw_content: bytes,
        filename: str,
        uploaded_by: str,
        description: str = "",
        target_pipeline: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Registers a newly uploaded dataset into storage and repository."""
        ...

    def load_dataset_df(
        self,
        dataset_id: str,
    ) -> Optional[pd.DataFrame]:
        """Loads and returns the in-memory pandas DataFrame for a registered dataset."""
        ...

    def execute_pipeline_on_dataset(
        self,
        dataset_id: str,
        trigger_user: str = "engineer",
    ) -> Dict[str, Any]:
        """Executes the 5-stage observable pipeline for the specified dataset."""
        ...
