"""Recovery Execution Engine for DataGuard.

Executes authorized remediation operations:
- DROP_CORRUPTED: Quarantines invalid records to dead-letter storage and outputs clean data
- RETRY: Re-triggers pipeline execution with clean connections
- APPLY_FALLBACK: Reverts to verified baseline datasets
- SCHEMA_PATCH: Applies emergency column aliasing
"""

from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import json
import pandas as pd

from config.settings import PROCESSED_DATA_DIR
from src.database.connection import get_db
from src.database.repository import DataGuardRepository
from src.core.simulator import PipelineSimulator


class RecoveryExecutor:
    """Carries out authorized pipeline remediation actions."""

    def __init__(
        self,
        repo: Optional[DataGuardRepository] = None,
        simulator: Optional[PipelineSimulator] = None,
    ):
        self.repo = repo or DataGuardRepository()
        self.simulator = simulator or PipelineSimulator(repo=self.repo)
        PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    def execute(self, action_id: int) -> Tuple[bool, str, Optional[pd.DataFrame]]:
        """Executes an action that has been approved in the database.

        Returns:
            Tuple of (success: bool, execution_log: str, recovered_df: Optional[pd.DataFrame])
        """
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT * FROM recovery_actions WHERE id = ?;", (action_id,)
            )
            action = cursor.fetchone()

        if not action:
            return False, f"Recovery action #{action_id} not found.", None

        if action["status"] != "APPROVED":
            return (
                False,
                f"Action #{action_id} is in status '{action['status']}'. Requires 'APPROVED' to execute.",
                None,
            )

        action_type = action["action_type"]
        params = json.loads(action["parameters_json"]) if action["parameters_json"] else {}
        pipeline_id = action["pipeline_id"]

        try:
            if action_type == "DROP_CORRUPTED":
                return self._execute_drop_corrupted(action_id, params)

            elif action_type == "RETRY":
                return self._execute_retry(action_id, pipeline_id)

            elif action_type == "SCHEMA_PATCH":
                return self._execute_schema_patch(action_id, params)

            elif action_type == "APPLY_FALLBACK":
                return self._execute_fallback(action_id, pipeline_id)

            else:
                return False, f"Unsupported action type: {action_type}", None

        except Exception as e:
            return False, f"Execution failed with unexpected exception: {str(e)}", None

    def _execute_drop_corrupted(
        self, action_id: int, params: Dict[str, Any]
    ) -> Tuple[bool, str, Optional[pd.DataFrame]]:
        """Quarantines corrupted row indices and writes clean data."""
        raw_path = params.get("raw_data_path")
        corrupted_indices = params.get("corrupted_indices", [])

        if not raw_path or not Path(raw_path).exists():
            return False, f"Raw data file not found at: {raw_path}", None

        df = pd.read_csv(raw_path)
        total_initial = len(df)

        # Isolate corrupted rows into quarantine dead-letter file
        corrupted_mask = df.index.isin(corrupted_indices)
        quarantine_df = df[corrupted_mask]
        clean_df = df[~corrupted_mask].copy()

        quarantine_path = PROCESSED_DATA_DIR / f"quarantine_action_{action_id}.csv"
        clean_path = PROCESSED_DATA_DIR / f"recovered_clean_action_{action_id}.csv"

        quarantine_df.to_csv(quarantine_path, index=False)
        clean_df.to_csv(clean_path, index=False)

        log = (
            f"Successfully quarantined {len(quarantine_df)} corrupted records to {quarantine_path.name}. "
            f"Preserved {len(clean_df)} clean records (from initial {total_initial}) to {clean_path.name}."
        )
        return True, log, clean_df

    def _execute_retry(
        self, action_id: int, pipeline_id: str
    ) -> Tuple[bool, str, Optional[pd.DataFrame]]:
        """Retries execution of the pipeline using clean simulated data."""
        new_run, df = self.simulator.run_pipeline(pipeline_id=pipeline_id, fault_type=None)
        log = f"Pipeline retry executed successfully. New run ID: {new_run.run_id} with {len(df)} rows."
        return True, log, df

    def _execute_schema_patch(
        self, action_id: int, params: Dict[str, Any]
    ) -> Tuple[bool, str, Optional[pd.DataFrame]]:
        """Applies dynamic schema aliasing to bridge column naming breaking changes."""
        raw_path = params.get("raw_data_path")
        if not raw_path or not Path(raw_path).exists():
            return False, f"Raw data file not found at {raw_path}", None

        df = pd.read_csv(raw_path)

        # Apply schema alias mapping: 'legacy_balance_v1' -> 'account_balance'
        if "legacy_balance_v1" in df.columns:
            df = df.rename(columns={"legacy_balance_v1": "account_balance"})

        # If primary key was dropped, generate fallback UUIDs
        if "customer_id" not in df.columns:
            import uuid
            df["customer_id"] = [f"PATCH-CUST-{uuid.uuid4().hex[:6].upper()}" for _ in range(len(df))]

        patched_path = PROCESSED_DATA_DIR / f"patched_action_{action_id}.csv"
        df.to_csv(patched_path, index=False)

        log = f"Applied emergency schema mapping: Generated patched dataset at {patched_path.name}."
        return True, log, df

    def _execute_fallback(
        self, action_id: int, pipeline_id: str
    ) -> Tuple[bool, str, Optional[pd.DataFrame]]:
        """Substitutes clean baseline data to unblock downstream processes."""
        df = self.simulator.generate_crm_data(num_rows=200, fault_type=None)
        fallback_path = PROCESSED_DATA_DIR / f"fallback_action_{action_id}.csv"
        df.to_csv(fallback_path, index=False)

        log = f"Fallback clean baseline dataset activated ({len(df)} rows)."
        return True, log, df
