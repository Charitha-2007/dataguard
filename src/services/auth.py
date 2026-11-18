"""Authentication & Role-Based Access Control (RBAC) Service for DataGuard.

Enforces principle of least privilege across three roles:
- ADMIN: Full access (trigger runs, approve recovery, configure settings)
- ENGINEER: Operational access (trigger runs, triage incidents, approve recovery)
- VIEWER: Read-only access (view dashboards, inspect logs, read knowledge base)
"""

from typing import Dict, Any, Optional
from dataclasses import dataclass
import hashlib
from src.database.connection import get_db


@dataclass
class UserSession:
    username: str
    role: str  # 'admin', 'engineer', 'viewer'
    email: str

    @property
    def can_approve_recovery(self) -> bool:
        return self.role in ["admin", "engineer"]

    @property
    def can_trigger_pipeline(self) -> bool:
        return self.role in ["admin", "engineer"]

    @property
    def can_manage_settings(self) -> bool:
        return self.role == "admin"


class AuthService:
    """Manages user authentication and role authorizations."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Computes a SHA-256 hash of the password."""
        return hashlib.sha256(password.encode("utf-8")).hexdigest()

    def authenticate(self, username: str, password: str) -> Optional[UserSession]:
        """Authenticates user against database credentials."""
        pwd_hash = self.hash_password(password)

        with get_db() as conn:
            cursor = conn.execute(
                "SELECT username, role, email FROM users WHERE username = ? AND password_hash = ?;",
                (username, pwd_hash),
            )
            row = cursor.fetchone()

        if row:
            return UserSession(
                username=row["username"],
                role=row["role"],
                email=row["email"],
            )
        return None

    def get_user_by_username(self, username: str) -> Optional[UserSession]:
        """Fetches user details by username."""
        with get_db() as conn:
            cursor = conn.execute(
                "SELECT username, role, email FROM users WHERE username = ?;",
                (username,),
            )
            row = cursor.fetchone()

        if row:
            return UserSession(
                username=row["username"],
                role=row["role"],
                email=row["email"],
            )
        return None
