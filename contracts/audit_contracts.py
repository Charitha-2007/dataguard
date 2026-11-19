"""Audit Ledger Contract - Owned by Member 5 (Database, Audit & QA Engineer)."""

from typing import Protocol, Dict, Any, List, Optional


class IAuditLedger(Protocol):
    """Contract for tamper-evident SHA-256 cryptographic audit logging."""

    def log(
        self,
        event_type: str,
        actor: str,
        details: Dict[str, Any],
        entity_id: Optional[str] = None,
        severity: str = "INFO",
    ) -> Dict[str, Any]:
        """Appends a new cryptographic block to the audit ledger and returns record dictionary."""
        ...

    def verify_integrity(self) -> Dict[str, Any]:
        """Validates hash continuity across the entire ledger from genesis to head."""
        ...

    def get_audit_trail(
        self,
        event_type: Optional[str] = None,
        actor: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Retrieves chronological audit trail records."""
        ...
