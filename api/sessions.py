"""Redis-backed JWT session management with refresh tokens.

Provides token refresh capability so users don't need to re-authenticate
every 30 minutes. Refresh tokens are stored in Redis with configurable
TTL (default: 7 days).

When Redis is unavailable, falls back to in-memory dict (dev mode).

Usage:
    from api.sessions import SessionManager

    sessions = SessionManager()
    refresh_token = sessions.create_refresh_token(role="admin", email="user@co.com")
    new_jwt = sessions.refresh(refresh_token)
    sessions.revoke(refresh_token)
"""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

from pydantic import BaseModel

from agentguard.logging import logger
from api.auth import create_token

REFRESH_TOKEN_TTL = int(
    os.environ.get("AGENTGUARD_REFRESH_TOKEN_TTL", 604800)
)  # 7 days
REDIS_URL = os.environ.get("AGENTGUARD_REDIS_URL", "")


class RefreshTokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 1800
    refresh_expires_in: int = REFRESH_TOKEN_TTL
    role: str


class SessionManager:
    """Manages refresh tokens backed by Redis or in-memory dict.

    Attributes:
        backend: 'redis' or 'memory'
    """

    def __init__(self, redis_url: str | None = None) -> None:
        self._redis_url = redis_url or REDIS_URL
        self._redis = None
        self._memory_store: dict[str, dict[str, Any]] = {}
        self.backend = "redis" if self._redis_url else "memory"

    def _get_redis(self):
        if self._redis is None and self._redis_url:
            try:
                import redis

                self._redis = redis.from_url(self._redis_url)
                self._redis.ping()
                self.backend = "redis"
            except Exception:
                logger.warning(
                    "Redis unavailable for sessions — falling back to memory"
                )
                self._redis = None
                self.backend = "memory"
        return self._redis

    def create_refresh_token(self, role: str, email: str = "") -> RefreshTokenResponse:
        """Create a new JWT + refresh token pair.

        Args:
            role: User role (admin/analyst/auditor).
            email: User email (for session tracking).

        Returns:
            RefreshTokenResponse with access_token and refresh_token.
        """
        access_token = create_token(role)
        refresh_token = secrets.token_urlsafe(48)

        session_data = {
            "role": role,
            "email": email,
            "created_at": time.time(),
            "expires_at": time.time() + REFRESH_TOKEN_TTL,
        }

        r = self._get_redis()
        if r is not None:
            import json

            r.setex(
                f"agentguard:session:{refresh_token}",
                REFRESH_TOKEN_TTL,
                json.dumps(session_data),
            )
        else:
            self._memory_store[refresh_token] = session_data

        logger.bind(module="agentguard.sessions").info(
            "Session created for {role} ({email})", role=role, email=email
        )

        return RefreshTokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            role=role,
        )

    def refresh(self, refresh_token: str) -> RefreshTokenResponse | None:
        """Exchange a refresh token for a new JWT.

        Args:
            refresh_token: The refresh token to validate and exchange.

        Returns:
            New RefreshTokenResponse if valid, None if invalid/expired.
        """
        session_data = self._get_session(refresh_token)
        if session_data is None:
            return None

        # Check expiry
        if time.time() > session_data.get("expires_at", 0):
            self.revoke(refresh_token)
            return None

        role = session_data["role"]
        new_access_token = create_token(role)

        return RefreshTokenResponse(
            access_token=new_access_token,
            refresh_token=refresh_token,  # Same refresh token
            role=role,
        )

    def revoke(self, refresh_token: str) -> bool:
        """Revoke a refresh token (logout).

        Args:
            refresh_token: The refresh token to revoke.

        Returns:
            True if revoked, False if not found.
        """
        r = self._get_redis()
        if r is not None:
            result = r.delete(f"agentguard:session:{refresh_token}")
            return result > 0

        if refresh_token in self._memory_store:
            del self._memory_store[refresh_token]
            return True
        return False

    def _get_session(self, refresh_token: str) -> dict[str, Any] | None:
        """Look up a session by refresh token."""
        r = self._get_redis()
        if r is not None:
            import json

            data = r.get(f"agentguard:session:{refresh_token}")
            if data is None:
                return None
            return json.loads(data)

        return self._memory_store.get(refresh_token)

    def get_active_sessions(self) -> int:
        """Return the count of active sessions (memory backend only)."""
        return len(self._memory_store)
