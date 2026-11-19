"""Root Cause Analysis (RCA) Engine for DataGuard.

Automatically diagnoses pipeline failures and data anomalies, classifying:
- Failure Mode (SCHEMA_MISMATCH, NULL_SPIKE, DATA_DRIFT, SLA_BREACH, VOLUME_ANOMALY, RUNTIME_EXCEPTION)
- Severity Level (P1 - Critical Blocker to P4 - Minor Warning)
- Technical Evidence & Probable Trigger Mechanism
- Recommended Recovery Action for Human Approval
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from src.core.quality_engine import QualityReport
from src.core.drift_detector import DriftAnomalyReport


@dataclass
class RCADiagnosis:
    incident_type: str
    severity: str  # 'P1', 'P2', 'P3', 'P4'
    title: str
    root_cause_summary: str
    probable_trigger: str
    recommended_action: str  # 'RETRY', 'DROP_CORRUPTED', 'APPLY_FALLBACK', 'SCHEMA_PATCH'
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RootCauseAnalysisEngine:
    """Evaluates telemetry, data quality results, and statistical drift to isolate root causes."""

    def diagnose(
        self,
        pipeline_id: str,
        sla_seconds: int,
        duration_seconds: float,
        row_count: int,
        quality_report: Optional[QualityReport] = None,
        drift_report: Optional[DriftAnomalyReport] = None,
        error_message: Optional[str] = None,
    ) -> Optional[RCADiagnosis]:
        """Performs multi-criteria diagnostic evaluation.

        Returns:
            RCADiagnosis if an issue is detected; None if the run was completely healthy.
        """
        # 1. Check for Runtime Exceptions / Crashes
        if error_message:
            return RCADiagnosis(
                incident_type="RUNTIME_EXCEPTION",
                severity="P1",
                title=f"Pipeline {pipeline_id} execution crashed with unhandled exception",
                root_cause_summary=f"Execution terminated abnormally: {error_message}",
                probable_trigger="Process crash, infrastructure failure, or unhandled runtime error.",
                recommended_action="RETRY",
                evidence={"error_message": error_message, "duration_seconds": duration_seconds},
            )

        # 2. Check for Schema Mismatch / Breaking Contract Change
        if quality_report and not quality_report.is_valid:
            schema_failures = [
                c for c in quality_report.checks if c.category == "SCHEMA" and c.status == "FAILED"
            ]
            if schema_failures:
                msg = schema_failures[0].message
                return RCADiagnosis(
                    incident_type="SCHEMA_MISMATCH",
                    severity="P1",
                    title=f"Schema contract violation in {pipeline_id}",
                    root_cause_summary=f"Incoming dataset does not conform to expected schema: {msg}",
                    probable_trigger="Upstream API release, database column rename, or unannounced contract alteration.",
                    recommended_action="SCHEMA_PATCH",
                    evidence={
                        "schema_message": msg,
                        "failed_checks": len(schema_failures),
                    },
                )

        # 3. Check for SLA Timeout / Latency Breach
        if duration_seconds > sla_seconds:
            overage_pct = round(((duration_seconds - sla_seconds) / sla_seconds) * 100, 1)
            severity = "P1" if overage_pct > 100.0 else "P2"
            return RCADiagnosis(
                incident_type="SLA_BREACH",
                severity=severity,
                title=f"Pipeline SLA breached by {overage_pct}% ({duration_seconds:.1f}s vs {sla_seconds}s limit)",
                root_cause_summary=f"Pipeline execution took {duration_seconds:.1f}s, exceeding maximum allowed SLA of {sla_seconds}s.",
                probable_trigger="Database lock contention, slow query execution, network congestion, or upstream throttling.",
                recommended_action="RETRY",
                evidence={
                    "duration_seconds": duration_seconds,
                    "sla_seconds": sla_seconds,
                    "overage_percent": overage_pct,
                },
            )

        # 4. Check for Null Spikes & Data Corruption in Quality Report
        if quality_report and not quality_report.is_valid:
            null_failures = [
                c for c in quality_report.checks if "null" in c.check_name and c.status == "FAILED"
            ]
            range_failures = [
                c for c in quality_report.checks if "range" in c.check_name and c.status == "FAILED"
            ]

            if null_failures:
                detail = null_failures[0]
                return RCADiagnosis(
                    incident_type="NULL_SPIKE",
                    severity="P2",
                    title=f"Severe missingness / null spike detected in {pipeline_id}",
                    root_cause_summary=detail.message,
                    probable_trigger="Upstream ETL worker dropped field during extraction or default constraint was removed.",
                    recommended_action="DROP_CORRUPTED",
                    evidence={
                        "check_name": detail.check_name,
                        "null_pct": detail.metric_value,
                        "threshold": detail.threshold,
                        "corrupted_rows": len(quality_report.corrupted_indices),
                    },
                )

            if range_failures:
                detail = range_failures[0]
                return RCADiagnosis(
                    incident_type="DATA_CORRUPTION",
                    severity="P2",
                    title=f"Numerical boundary violations in {pipeline_id}",
                    root_cause_summary=detail.message,
                    probable_trigger="Input data serialization error, inverted signs, or currency conversion bug.",
                    recommended_action="DROP_CORRUPTED",
                    evidence={
                        "check_name": detail.check_name,
                        "violation_count": detail.affected_rows_count,
                        "corrupted_rows": len(quality_report.corrupted_indices),
                    },
                )

        # 5. Check for Volume Drops / Surges (only for scheduled production pipelines with established baselines)
        is_custom_dataset = pipeline_id.startswith("dataset_") or "DS-" in pipeline_id
        if not is_custom_dataset and row_count < 20:
            return RCADiagnosis(
                incident_type="VOLUME_ANOMALY",
                severity="P2",
                title=f"Abnormal volume drop: only {row_count} rows ingested",
                root_cause_summary=f"Pipeline ingested {row_count} rows, which is critically below expected baseline volume (>200 rows).",
                probable_trigger="Upstream database connection closed prematurely or source table was truncated.",
                recommended_action="APPLY_FALLBACK",
                evidence={"row_count": row_count, "expected_min": 200},
            )

        # 6. Check for Statistical Data Drift
        if drift_report and drift_report.has_drift_or_anomaly:
            critical_cols = [
                col
                for col, res in drift_report.column_drifts.items()
                if res.drift_severity == "CRITICAL"
            ]
            if critical_cols:
                col = critical_cols[0]
                drift_res = drift_report.column_drifts[col]
                return RCADiagnosis(
                    incident_type="DATA_DRIFT",
                    severity="P3",
                    title=f"Statistical data drift detected in column '{col}'",
                    root_cause_summary=f"Significant distribution shift in '{col}': PSI={drift_res.psi_score}, KS p-value={drift_res.ks_pvalue:.4f}",
                    probable_trigger="Gradual demographic shift, sudden business model change, or upstream unit scale change.",
                    recommended_action="APPLY_FALLBACK",
                    evidence={
                        "column": col,
                        "psi_score": drift_res.psi_score,
                        "ks_pvalue": drift_res.ks_pvalue,
                    },
                )

        # If everything evaluated cleanly
        return None
