"""Historical Failure Knowledge Base & Solution Repository for DataGuard.

Provides:
- Searchable institutional memory of past pipeline failure patterns
- Query engine matching incoming errors to known resolution procedures
- Dynamic recording of new remediation patterns upon successful verification
"""

from typing import Dict, List, Any, Optional
from src.database.connection import get_db
from src.database.repository import DataGuardRepository


class KnowledgeBaseService:
    """Manages the searchable repository of historical failure solutions."""

    def __init__(self, repo: Optional[DataGuardRepository] = None):
        self.repo = repo or DataGuardRepository()

    def get_all_solutions(self) -> List[Dict[str, Any]]:
        """Retrieves all indexed failure resolutions, ranked by frequency of use."""
        return self.repo.get_all_knowledge_base()

    def search_solutions(self, query: str) -> List[Dict[str, Any]]:
        """Performs case-insensitive keyword search across incident types, error patterns, and resolutions."""
        query_pattern = f"%{query.lower()}%"
        with get_db() as conn:
            cursor = conn.execute(
                """SELECT * FROM knowledge_base 
                   WHERE LOWER(incident_type) LIKE ? 
                      OR LOWER(error_pattern) LIKE ? 
                      OR LOWER(root_cause) LIKE ? 
                      OR LOWER(resolution_steps) LIKE ?
                   ORDER BY times_used DESC;""",
                (query_pattern, query_pattern, query_pattern, query_pattern),
            )
            return [dict(row) for row in cursor.fetchall()]

    def record_solution(
        self,
        incident_type: str,
        error_pattern: str,
        root_cause: str,
        recommended_action: str,
        resolution_steps: str,
    ) -> int:
        """Indexes a newly verified resolution procedure into the repository."""
        with get_db() as conn:
            # Check if matching error pattern already exists
            cursor = conn.execute(
                "SELECT id, times_used FROM knowledge_base WHERE incident_type = ? AND error_pattern = ?;",
                (incident_type, error_pattern),
            )
            existing = cursor.fetchone()

            if existing:
                # Increment usage counter
                conn.execute(
                    "UPDATE knowledge_base SET times_used = times_used + 1 WHERE id = ?;",
                    (existing["id"],),
                )
                return existing["id"]
            else:
                # Insert new entry
                cursor = conn.execute(
                    """INSERT INTO knowledge_base 
                       (incident_type, error_pattern, root_cause, recommended_action, resolution_steps, times_used) 
                       VALUES (?, ?, ?, ?, ?, 1);""",
                    (
                        incident_type,
                        error_pattern,
                        root_cause,
                        recommended_action,
                        resolution_steps,
                    ),
                )
                return cursor.lastrowid
