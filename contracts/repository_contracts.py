"""Data Repository Contract - Owned by Member 5 (Database, Audit & QA Engineer)."""

from typing import Protocol, Dict, Any, List, Optional


class IDataRepository(Protocol):
    """Contract for data persistence across pipelines, incidents, and telemetry."""

    def get_all_pipelines(self) -> List[Dict[str, Any]]:
        """Retrieves all registered pipelines with status and SLA metrics."""
        ...

    def get_all_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves all recorded incidents across the platform."""
        ...

    def create_incident(
        self,
        pipeline_id: str,
        title: str,
        description: str,
        severity: str,
        status: str = "OPEN",
        root_cause: Optional[str] = None,
        run_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Persists a new incident and returns the incident record."""
        ...

    def update_incident_status(
        self,
        incident_id: str,
        status: str,
        resolved_by: Optional[str] = None,
        resolution_notes: Optional[str] = None,
    ) -> bool:
        """Updates incident lifecycle state."""
        ...
