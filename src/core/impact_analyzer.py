"""Downstream Dependency Impact Analyzer (DAG) for DataGuard.

Traverses pipeline dependency relationships (Directed Acyclic Graph)
to calculate the blast radius when an upstream pipeline fails:
- Direct vs Transitive downstream dependencies
- Critical business systems blocked
- Graph data structures for Plotly interactive DAG visualization
"""

from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass, asdict
from collections import deque
from src.database.repository import DataGuardRepository


@dataclass
class ImpactedPipeline:
    pipeline_id: str
    pipeline_name: str
    dependency_depth: int  # 1 = direct consumer, 2+ = indirect consumer
    dependency_type: str  # 'hard' or 'soft'
    owner_email: str


@dataclass
class ImpactReport:
    failed_pipeline_id: str
    failed_pipeline_name: str
    total_impacted_pipelines: int
    blast_radius_score: str  # 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    direct_dependents: List[str]
    transitive_dependents: List[str]
    impacted_pipelines: List[ImpactedPipeline]
    impact_summary: str
    graph_nodes: List[Dict[str, Any]]
    graph_edges: List[Dict[str, str]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "failed_pipeline_id": self.failed_pipeline_id,
            "failed_pipeline_name": self.failed_pipeline_name,
            "total_impacted_pipelines": self.total_impacted_pipelines,
            "blast_radius_score": self.blast_radius_score,
            "direct_dependents": self.direct_dependents,
            "transitive_dependents": self.transitive_dependents,
            "impact_summary": self.impact_summary,
            "impacted_pipelines": [asdict(p) for p in self.impacted_pipelines],
            "graph_nodes": self.graph_nodes,
            "graph_edges": self.graph_edges,
        }


class DependencyImpactAnalyzer:
    """Analyzes Directed Acyclic Graph (DAG) dependencies for pipeline failures."""

    def __init__(self, repo: Optional[DataGuardRepository] = None):
        self.repo = repo or DataGuardRepository()

    def analyze_impact(self, failed_pipeline_id: str) -> ImpactReport:
        """Performs Breadth-First Search (BFS) to discover all downstream pipelines blocked by this failure."""
        failed_pipeline = self.repo.get_pipeline(failed_pipeline_id)
        failed_name = failed_pipeline["name"] if failed_pipeline else failed_pipeline_id

        visited: Set[str] = set()
        queue = deque([(failed_pipeline_id, 0)])  # (id, depth)
        
        impacted_list: List[ImpactedPipeline] = []
        direct_deps: List[str] = []
        transitive_deps: List[str] = []
        graph_nodes: List[Dict[str, Any]] = [
            {"id": failed_pipeline_id, "label": failed_name, "status": "FAILED"}
        ]
        graph_edges: List[Dict[str, str]] = []

        while queue:
            curr_id, depth = queue.popleft()

            # Find immediate children of curr_id
            children = self.repo.get_downstream_dependencies(curr_id)
            for child_id in children:
                graph_edges.append({"source": curr_id, "target": child_id})

                if child_id not in visited:
                    visited.add(child_id)
                    child_meta = self.repo.get_pipeline(child_id)
                    child_name = child_meta["name"] if child_meta else child_id
                    owner = child_meta["owner_email"] if child_meta else "unknown"

                    impacted_obj = ImpactedPipeline(
                        pipeline_id=child_id,
                        pipeline_name=child_name,
                        dependency_depth=depth + 1,
                        dependency_type="hard",
                        owner_email=owner,
                    )
                    impacted_list.append(impacted_obj)

                    graph_nodes.append(
                        {"id": child_id, "label": child_name, "status": "BLOCKED"}
                    )

                    if depth + 1 == 1:
                        direct_deps.append(child_id)
                    else:
                        transitive_deps.append(child_id)

                    queue.append((child_id, depth + 1))

        total_impacted = len(visited)
        if total_impacted == 0:
            blast_score = "NONE"
            summary = f"No downstream pipelines depend on {failed_name}. Blast radius is isolated."
        elif total_impacted == 1:
            blast_score = "MEDIUM"
            summary = f"Directly blocks 1 downstream pipeline: '{impacted_list[0].pipeline_name}'."
        elif total_impacted <= 3:
            blast_score = "HIGH"
            names = ", ".join([f"'{p.pipeline_name}'" for p in impacted_list])
            summary = f"Blocks {total_impacted} downstream pipelines ({names})."
        else:
            blast_score = "CRITICAL"
            summary = f"Severe enterprise blast radius: Blocks {total_impacted} downstream pipelines across data marts."

        return ImpactReport(
            failed_pipeline_id=failed_pipeline_id,
            failed_pipeline_name=failed_name,
            total_impacted_pipelines=total_impacted,
            blast_radius_score=blast_score,
            direct_dependents=direct_deps,
            transitive_dependents=transitive_deps,
            impacted_pipelines=impacted_list,
            impact_summary=summary,
            graph_nodes=graph_nodes,
            graph_edges=graph_edges,
        )
