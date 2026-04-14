"""JWT authentication and RBAC for the AgentGuard API.

Roles:
  admin   — full access to all endpoints
  analyst — read-only access to events and audit
  auditor — audit and export endpoints only

Token exchange:
  POST /auth/token with API key → JWT (30-min expiry)
"""

from __future__ import annotations

import os
import time
from enum import StrEnum
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

JWT_SECRET = os.environ.get("AGENTGUARD_JWT_SECRET", "agentguard-dev-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 1800  # 30 minutes

# Simple API key → role mapping (in production, use a database)
API_KEYS: dict[str, str] = {
    os.environ.get("AGENTGUARD_ADMIN_KEY", "admin-key-dev"): "admin",
    os.environ.get("AGENTGUARD_ANALYST_KEY", "analyst-key-dev"): "analyst",
    os.environ.get("AGENTGUARD_AUDITOR_KEY", "auditor-key-dev"): "auditor",
}


class Role(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"


class TokenRequest(BaseModel):
    api_key: str = Field(description="API key to exchange for a JWT")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = JWT_EXPIRY_SECONDS
    role: str


class TokenPayload(BaseModel):
    sub: str  # role
    exp: float
    iat: float


security = HTTPBearer(auto_error=False)


def create_token(role: str) -> str:
    """Create a signed JWT for a given role."""
    now = time.time()
    payload = {
        "sub": role,
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def verify_token(token: str) -> TokenPayload:
    """Verify and decode a JWT.

    Raises:
        HTTPException: If token is invalid or expired.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return TokenPayload(**payload)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> TokenPayload:
    """FastAPI dependency: extract and verify the JWT from Authorization header."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(credentials.credentials)


def require_role(*allowed_roles: str):
    """FastAPI dependency factory: require the user to have one of the allowed roles."""

    def _check(
        user: Annotated[TokenPayload, Depends(get_current_user)],
    ) -> TokenPayload:
        if user.sub not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.sub}' not authorized. Requires: {allowed_roles}",
            )
        return user

    return _check
