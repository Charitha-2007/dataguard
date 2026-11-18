"""Service Level Agreement (SLA) Monitor for DataGuard.

Tracks pipeline latency compliance, calculates P95 run durations,
grades operational reliability, and triggers escalation for lagging incidents.
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
import numpy as np
from src.database.repository import DataGuardRepository


@dataclass
class PipelineSLAReport:
    pipeline_id: str
    pipeline_name: str
    sla_target_seconds: int
    total_runs_evaluated: int
    successful_runs: int
    breached_runs: int
    compliance_percentage: float
    average_duration_seconds: float
    p95_duration_seconds: float
    max_duration_seconds: float
    health_grade: str  # 'A', 'B', 'C', 'F'
    status: str  # 'HEALTHY', 'AT_RISK', 'BREACHED'

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SLAMonitor:
    """Calculates SLA compliance metrics and grades pipeline reliability."""

    def __init__(self, repo: Optional[DataGuardRepository] = None):
        self.repo = repo or DataGuardRepository()

    def evaluate_run_sla(
        self, sla_target_seconds: int, duration_seconds: float
    ) -> Dict[str, Any]:
        """Evaluates a single execution against its SLA budget."""
        is_breached = duration_seconds > sla_target_seconds
        overage_seconds = max(0.0, duration_seconds - sla_target_seconds)
        overage_pct = (
            round((overage_seconds / sla_target_seconds) * 100, 1)
            if sla_target_seconds > 0
            else 0.0
        )

        return {
            "is_breached": is_breached,
            "sla_target_seconds": sla_target_seconds,
            "duration_seconds": duration_seconds,
            "overage_seconds": round(overage_seconds, 2),
            "overage_percent": overage_pct,
            "status": "BREACHED" if is_breached else "COMPLIANT",
        }

    def get_pipeline_compliance(
        self, pipeline_id: str, limit_runs: int = 50
    ) -> PipelineSLAReport:
        """Computes aggregate historical SLA compliance and P95 latency."""
        pipeline = self.repo.get_pipeline(pipeline_id)
        if not pipeline:
            raise ValueError(f"Pipeline '{pipeline_id}' not found in registry.")

        sla_target = pipeline["sla_seconds"]
        pipeline_name = pipeline["name"]

        # Fetch recent runs
        all_runs = self.repo.get_recent_runs(limit=limit_runs)
        pipeline_runs = [r for r in all_runs if r["pipeline_id"] == pipeline_id]

        if not pipeline_runs:
            return PipelineSLAReport(
                pipeline_id=pipeline_id,
                pipeline_name=pipeline_name,
                sla_target_seconds=sla_target,
                total_runs_evaluated=0,
                successful_runs=0,
                breached_runs=0,
                compliance_percentage=100.0,
                average_duration_seconds=0.0,
                p95_duration_seconds=0.0,
                max_duration_seconds=0.0,
                health_grade="A",
                status="HEALTHY",
            )

        durations = [r["duration_seconds"] for r in pipeline_runs if r["duration_seconds"] is not None]
        total_runs = len(pipeline_runs)
        breached_count = sum(1 for d in durations if d > sla_target)
        success_count = sum(1 for r in pipeline_runs if r["status"] == "SUCCESS")

        compliance_pct = round(((total_runs - breached_count) / total_runs) * 100, 1)
        avg_duration = round(float(np.mean(durations)), 2) if durations else 0.0
        p95_duration = round(float(np.percentile(durations, 95)), 2) if durations else 0.0
        max_duration = round(float(np.max(durations)), 2) if durations else 0.0

        # Grade calculation
        if compliance_pct >= 98.0:
            grade = "A"
            status = "HEALTHY"
        elif compliance_pct >= 90.0:
            grade = "B"
            status = "AT_RISK"
        elif compliance_pct >= 75.0:
            grade = "C"
            status = "AT_RISK"
        else:
            grade = "F"
            status = "BREACHED"

        return PipelineSLAReport(
            pipeline_id=pipeline_id,
            pipeline_name=pipeline_name,
            sla_target_seconds=sla_target,
            total_runs_evaluated=total_runs,
            successful_runs=success_count,
            breached_runs=breached_count,
            compliance_percentage=compliance_pct,
            average_duration_seconds=avg_duration,
            p95_duration_seconds=p95_duration,
            max_duration_seconds=max_duration,
            health_grade=grade,
            status=status,
        )
