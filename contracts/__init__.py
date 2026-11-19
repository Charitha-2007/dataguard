"""DataGuard Shared Interface Contracts.

These typed protocols decouple development between the 5 team members,
enabling isolated development and testing without breaking runtime dependencies.
"""

from contracts.ingestion_contracts import IIngestionService
from contracts.quality_contracts import IQualityEngine, IDriftDetector, ISLAMonitor
from contracts.repository_contracts import IDataRepository
from contracts.audit_contracts import IAuditLedger

__all__ = [
    "IIngestionService",
    "IQualityEngine",
    "IDriftDetector",
    "ISLAMonitor",
    "IDataRepository",
    "IAuditLedger",
]
