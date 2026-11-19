"""Tests verifying that existing implementations adhere to the shared interface contracts."""

import pytest
from contracts.ingestion_contracts import IIngestionService
from contracts.quality_contracts import IQualityEngine, IDriftDetector, ISLAMonitor
from contracts.repository_contracts import IDataRepository
from contracts.audit_contracts import IAuditLedger

from src.services.dataset_service import DatasetService
from src.core.quality_engine import DataQualityEngine
from src.core.drift_detector import DriftAnomalyDetector
from src.core.sla_monitor import SLAMonitor
from src.database.repository import DataGuardRepository
from src.services.audit_service import AuditService


class TestInterfaceContracts:
    """Verifies that all concrete services satisfy the 5-member team contracts."""

    def test_dataset_service_contract_conformance(self):
        """Verifies DatasetService satisfies IIngestionService methods."""
        assert hasattr(DatasetService, "parse_file")
        assert hasattr(DatasetService, "profile_dataset")
        assert hasattr(DatasetService, "save_dataset")
        assert hasattr(DatasetService, "load_dataset_df")
        assert hasattr(DatasetService, "execute_pipeline_on_dataset")

    def test_quality_engine_contract_conformance(self):
        """Verifies DataQualityEngine satisfies IQualityEngine methods."""
        assert hasattr(DataQualityEngine, "evaluate")

    def test_drift_detector_contract_conformance(self):
        """Verifies DriftAnomalyDetector satisfies IDriftDetector methods."""
        assert hasattr(DriftAnomalyDetector, "evaluate")
        assert hasattr(DriftAnomalyDetector, "calculate_psi")
        assert hasattr(DriftAnomalyDetector, "calculate_ks_drift")

    def test_sla_monitor_contract_conformance(self):
        """Verifies SLAMonitor satisfies ISLAMonitor methods."""
        assert hasattr(SLAMonitor, "evaluate_run_sla")
        assert hasattr(SLAMonitor, "get_pipeline_compliance")

    def test_repository_contract_conformance(self):
        """Verifies DataGuardRepository satisfies IDataRepository methods."""
        assert hasattr(DataGuardRepository, "get_all_pipelines")
        assert hasattr(DataGuardRepository, "get_all_incidents")
        assert hasattr(DataGuardRepository, "create_incident")
        assert hasattr(DataGuardRepository, "update_incident_status")

    def test_audit_ledger_contract_conformance(self):
        """Verifies AuditService satisfies IAuditLedger methods."""
        assert hasattr(AuditService, "log")
        assert hasattr(AuditService, "verify_integrity")
        assert hasattr(AuditService, "get_audit_trail")
