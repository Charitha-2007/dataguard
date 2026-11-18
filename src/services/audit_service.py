"""Centralized Audit Service & Compliance Ledger for DataGuard.

Provides:
- Tamper-evident cryptographic audit logging (SHA-256 hash chaining)
- Filtered audit trail retrieval by actor, action, and entity
- Automated integrity verification to detect unauthorized database row modifications
- Export routines for regulatory compliance (SOC2, ISO 27001)
"""

from typing import Dict, List, Any, Optional
import json
import pandas as pd
from datetime import datetime

from src.database.repository import DataGuardRepository


class AuditService:
    """Manages the immutable audit ledger and compliance reporting."""

    def __init__(self, repo: Optional[DataGuardRepository] = None):
        self.repo = repo or DataGuardRepository()

    def log(
        self,
        actor: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Appends an event to the cryptographically hash-chained audit ledger."""
        self.repo.log_audit_event(
            actor=actor,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details,
        )

    def get_audit_trail(
        self,
        limit: int = 100,
        actor: Optional[str] = None,
        action: Optional[str] = None,
        entity_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieves audit records with optional filtering."""
        records = self.repo.get_recent_audit_logs(limit=limit)

        filtered = []
        for r in records:
            if actor and r["actor"] != actor:
                continue
            if action and r["action"] != action:
                continue
            if entity_type and r["entity_type"] != entity_type:
                continue
            
            # Parse details JSON for clean presentation
            item = dict(r)
            if item.get("details_json"):
                try:
                    item["details"] = json.loads(item["details_json"])
                except Exception:
                    item["details"] = {}
            filtered.append(item)

        return filtered

    def verify_integrity(self) -> Dict[str, Any]:
        """Runs cryptographic verification of the SHA-256 hash chain across all records."""
        return self.repo.verify_audit_log_integrity()

    def export_as_dataframe(self, limit: int = 200) -> pd.DataFrame:
        """Exports the audit trail as a Pandas DataFrame for CSV/Excel download in UI."""
        records = self.get_audit_trail(limit=limit)
        if not records:
            return pd.DataFrame(
                columns=["id", "timestamp", "actor", "action", "entity_type", "entity_id", "record_hash"]
            )
        
        df = pd.DataFrame(records)
        display_cols = [
            col
            for col in ["id", "timestamp", "actor", "action", "entity_type", "entity_id", "record_hash"]
            if col in df.columns
        ]
        return df[display_cols]
