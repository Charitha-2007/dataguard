"""Pipeline Simulator & Fault Injection Engine for DataGuard.

Simulates multi-source batch data pipelines (CRM Customer Sync, Billing Transactions,
User Clickstream Events) and provides controlled injection of real-world production
faults: Schema Drift, Null Spikes, Value Anomalies, and SLA Breaches.
"""

from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime, timedelta
import uuid
import time
import random
import pandas as pd
import numpy as np

from config.settings import MOCK_DATA_DIR
from src.database.models import PipelineRun
from src.database.repository import DataGuardRepository


class PipelineSimulator:
    """Generates synthetic dataset streams with optional controlled failure injection."""

    def __init__(self, repo: Optional[DataGuardRepository] = None):
        self.repo = repo or DataGuardRepository()
        MOCK_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------
    # DATASET GENERATORS
    # -----------------------------------------------------------------

    def generate_crm_data(
        self, num_rows: int = 500, fault_type: Optional[str] = None
    ) -> pd.DataFrame:
        """Generates Customer Profiles dataset.

        Standard Schema:
        - customer_id: str (UUID)
        - name: str
        - email: str
        - signup_date: str (YYYY-MM-DD)
        - country: str
        - account_balance: float (0.0 to 10000.0)

        Supported Fault Injections:
        - 'SCHEMA_MISMATCH': Drops 'customer_id' and renames 'account_balance' -> 'unknown_col'.
        - 'NULL_SPIKE': Injects 35% nulls in 'email' and 'account_balance'.
        - 'ANOMALY_VALUES': Injects extreme negative balances and corrupted countries.
        - 'VOLUME_DROP': Drastically cuts volume down to 10 rows.
        """
        if fault_type == "VOLUME_DROP":
            num_rows = 10

        np.random.seed(int(time.time()) % 10000)
        countries = ["US", "IN", "DE", "GB", "CA", "FR", "JP", "AU"]
        first_names = ["Alex", "Jordan", "Taylor", "Morgan", "Sam", "Chris", "Pat", "Riley"]
        last_names = ["Smith", "Patel", "Johnson", "Mueller", "Williams", "Brown", "Jones"]

        records = []
        base_date = datetime.now() - timedelta(days=30)
        for i in range(num_rows):
            fn = random.choice(first_names)
            ln = random.choice(last_names)
            records.append({
                "customer_id": f"CUST-{uuid.uuid4().hex[:8].upper()}",
                "name": f"{fn} {ln}",
                "email": f"{fn.lower()}.{ln.lower()}{i}@example.com",
                "signup_date": (base_date + timedelta(days=random.randint(0, 30))).strftime("%Y-%m-%d"),
                "country": random.choice(countries),
                "account_balance": round(float(np.random.uniform(50.0, 5000.0)), 2),
            })

        df = pd.DataFrame(records)

        # ----------------- FAULT INJECTION LOGIC -----------------
        if fault_type == "SCHEMA_MISMATCH":
            # Simulate upstream API breaking change
            df = df.drop(columns=["customer_id"])
            df = df.rename(columns={"account_balance": "legacy_balance_v1"})

        elif fault_type == "NULL_SPIKE":
            # Simulate extraction bug producing missing data in critical columns
            null_mask = np.random.rand(len(df)) < 0.35  # 35% null rate
            df.loc[null_mask, "email"] = None
            df.loc[null_mask, "account_balance"] = np.nan

        elif fault_type == "ANOMALY_VALUES":
            # Simulate data corruption / negative balances & rogue characters
            anomaly_indices = np.random.choice(df.index, size=int(len(df) * 0.10), replace=False)
            df.loc[anomaly_indices, "account_balance"] = -99999.0
            df.loc[anomaly_indices, "country"] = "CORRUPTED_CODE_###"

        return df

    def generate_billing_data(
        self, num_rows: int = 500, fault_type: Optional[str] = None
    ) -> pd.DataFrame:
        """Generates Billing & Payment Transactions dataset.

        Standard Schema:
        - transaction_id: str
        - customer_id: str
        - amount: float (10.0 to 2500.0)
        - currency: str (USD, EUR, GBP, INR)
        - status: str (SUCCESS, PENDING, FAILED)
        - timestamp: str
        """
        if fault_type == "VOLUME_DROP":
            num_rows = 5

        records = []
        currencies = ["USD", "EUR", "GBP", "INR"]
        statuses = ["SUCCESS", "SUCCESS", "SUCCESS", "PENDING", "FAILED"]
        now = datetime.now()

        for _ in range(num_rows):
            records.append({
                "transaction_id": f"TXN-{uuid.uuid4().hex[:10].upper()}",
                "customer_id": f"CUST-{uuid.uuid4().hex[:8].upper()}",
                "amount": round(float(np.random.exponential(scale=150.0) + 10.0), 2),
                "currency": random.choice(currencies),
                "status": random.choice(statuses),
                "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
            })

        df = pd.DataFrame(records)

        # ----------------- FAULT INJECTION LOGIC -----------------
        if fault_type == "SCHEMA_MISMATCH":
            df = df.rename(columns={"transaction_id": "tx_ref_num"})

        elif fault_type == "NULL_SPIKE":
            null_mask = np.random.rand(len(df)) < 0.40  # 40% null rate
            df.loc[null_mask, "amount"] = np.nan

        elif fault_type == "ANOMALY_VALUES":
            anomaly_indices = np.random.choice(df.index, size=int(len(df) * 0.08), replace=False)
            df.loc[anomaly_indices, "amount"] = -500.0

        return df

    # -----------------------------------------------------------------
    # PIPELINE EXECUTION RUNNER
    # -----------------------------------------------------------------

    def run_pipeline(
        self,
        pipeline_id: str,
        fault_type: Optional[str] = None,
        simulated_delay_sec: float = 0.0,
    ) -> Tuple[PipelineRun, pd.DataFrame]:
        """Executes a simulated pipeline run, saves data, and logs telemetry in the DB.

        Args:
            pipeline_id: Registered pipeline ID (e.g. 'crm_customers_etl')
            fault_type: Optional fault ('SCHEMA_MISMATCH', 'NULL_SPIKE', 'ANOMALY_VALUES', 'SLA_BREACH', 'VOLUME_DROP')
            simulated_delay_sec: Additional execution delay (used to trigger SLA breaches)

        Returns:
            Tuple of (PipelineRun DB record, generated DataFrame)
        """
        run_code = f"RUN-{datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}"
        start_time = time.time()
        started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Generate Dataset
        if pipeline_id == "billing_transactions_sync":
            df = self.generate_billing_data(num_rows=400, fault_type=fault_type)
        else:
            df = self.generate_crm_data(num_rows=400, fault_type=fault_type)

        # 2. Save raw mock data file
        raw_filename = f"{pipeline_id}_{run_code}_raw.csv"
        raw_filepath = MOCK_DATA_DIR / raw_filename
        df.to_csv(raw_filepath, index=False)

        # 3. Handle SLA Breach delay simulation
        if fault_type == "SLA_BREACH":
            # Simulate long query latency or hanging lock
            simulated_delay_sec = max(simulated_delay_sec, 2.5)

        if simulated_delay_sec > 0:
            time.sleep(simulated_delay_sec)

        duration = round(time.time() - start_time, 3)

        # 4. Construct PipelineRun model
        run = PipelineRun(
            run_id=run_code,
            pipeline_id=pipeline_id,
            status="RUNNING",  # Will be updated to SUCCESS or FAILED by detection engine
            started_at=started_at,
            duration_seconds=duration,
            row_count=len(df),
            raw_data_path=str(raw_filepath),
        )

        # 5. Persist run record in Database
        self.repo.create_run(run)

        # Log audit event for run trigger
        self.repo.log_audit_event(
            actor="simulator_engine",
            action="TRIGGER_RUN",
            entity_type="pipeline_run",
            entity_id=run_code,
            details={
                "pipeline_id": pipeline_id,
                "fault_injected": fault_type,
                "row_count": len(df),
                "duration_seconds": duration,
            },
        )

        return run, df
