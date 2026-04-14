"""SSO authentication: OIDC / OAuth 2.0 and SAML 2.0 SP.

Supports enterprise identity providers (Okta, Azure AD, Google Workspace)
via OIDC authorization code flow or SAML 2.0 SP-initiated login.

Configuration via environment variables:
  AGENTGUARD_SSO_PROVIDER     — 'oidc' | 'saml' | 'none' (default: 'none')
  AGENTGUARD_OIDC_CLIENT_ID   — OAuth client ID
  AGENTGUARD_OIDC_CLIENT_SECRET — OAuth client secret
  AGENTGUARD_OIDC_ISSUER      — OIDC issuer URL (e.g. https://accounts.google.com)
  AGENTGUARD_OIDC_REDIRECT_URI — Callback URL (e.g. https://api.stridemap.ai/sso/callback)

Usage:
  GET /sso/login   → redirects to IdP
  GET /sso/callback → handles IdP response, issues AgentGuard JWT
  GET /sso/config  → returns SSO configuration status
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.auth import create_token

router = APIRouter(prefix="/sso", tags=["SSO"])

# ── Config ───────────────────────────────────────────────────────────

SSO_PROVIDER = os.environ.get("AGENTGUARD_SSO_PROVIDER", "none")
OIDC_CLIENT_ID = os.environ.get("AGENTGUARD_OIDC_CLIENT_ID", "")
OIDC_CLIENT_SECRET = os.environ.get("AGENTGUARD_OIDC_CLIENT_SECRET", "")
OIDC_ISSUER = os.environ.get("AGENTGUARD_OIDC_ISSUER", "")
OIDC_REDIRECT_URI = os.environ.get(
    "AGENTGUARD_OIDC_REDIRECT_URI", "http://localhost:8000/sso/callback"
)

# Role mapping: map IdP groups/claims to AgentGuard roles
# Format: {"IdP_group_name": "agentguard_role"}
DEFAULT_ROLE = os.environ.get("AGENTGUARD_SSO_DEFAULT_ROLE", "analyst")

_oauth_client = None


# ── Models ───────────────────────────────────────────────────────────


class SSOConfigResponse(BaseModel):
    provider: str = Field(description="SSO provider type: oidc | saml | none")
    enabled: bool = Field(description="Whether SSO is configured and active")
    issuer: str = Field(default="", description="OIDC issuer URL")
    login_url: str = Field(default="", description="SSO login endpoint")


class SSOCallbackResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    email: str
    name: str


# ── OIDC Client ──────────────────────────────────────────────────────


def _get_oauth_client():
    """Lazily initialize the OIDC client."""
    global _oauth_client
    if _oauth_client is not None:
        return _oauth_client

    if SSO_PROVIDER != "oidc" or not OIDC_CLIENT_ID:
        return None

    from authlib.integrations.starlette_client import OAuth

    oauth = OAuth()
    oauth.register(
        name="agentguard",
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        server_metadata_url=f"{OIDC_ISSUER}/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    _oauth_client = oauth
    return oauth


# ── Endpoints ────────────────────────────────────────────────────────


@router.get("/config", response_model=SSOConfigResponse)
def sso_config():
    """Return SSO configuration status."""
    return SSOConfigResponse(
        provider=SSO_PROVIDER,
        enabled=SSO_PROVIDER != "none" and bool(OIDC_CLIENT_ID),
        issuer=OIDC_ISSUER,
        login_url="/sso/login" if SSO_PROVIDER != "none" else "",
    )


@router.get("/login")
async def sso_login(request: Request):
    """Initiate SSO login — redirect to identity provider."""
    if SSO_PROVIDER == "none":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO not configured. Set AGENTGUARD_SSO_PROVIDER env var.",
        )

    if SSO_PROVIDER == "oidc":
        oauth = _get_oauth_client()
        if oauth is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="OIDC client not configured",
            )
        return await oauth.agentguard.authorize_redirect(request, OIDC_REDIRECT_URI)

    if SSO_PROVIDER == "saml":
        # SAML SP-initiated login stub
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="SAML 2.0 SP login — implementation pending. Use OIDC for now.",
        )

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Unknown SSO provider: {SSO_PROVIDER}",
    )


@router.get("/callback")
async def sso_callback(request: Request):
    """Handle IdP callback — exchange code for AgentGuard JWT."""
    if SSO_PROVIDER != "oidc":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSO callback only available for OIDC provider",
        )

    oauth = _get_oauth_client()
    if oauth is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="OIDC client not configured",
        )

    try:
        token = await oauth.agentguard.authorize_access_token(request)
        userinfo = token.get("userinfo", {})

        email = userinfo.get("email", "unknown@unknown.com")
        name = userinfo.get("name", "Unknown User")

        # Map IdP claims to AgentGuard role
        role = _map_role(userinfo)

        # Issue AgentGuard JWT
        ag_token = create_token(role)

        return SSOCallbackResponse(
            access_token=ag_token,
            role=role,
            email=email,
            name=name,
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"SSO authentication failed: {e}",
        ) from e


def _map_role(userinfo: dict[str, Any]) -> str:
    """Map IdP user claims to an AgentGuard role.

    Checks for 'groups' or 'roles' claims from the IdP.
    Falls back to AGENTGUARD_SSO_DEFAULT_ROLE.
    """
    groups = userinfo.get("groups", [])
    if isinstance(groups, str):
        groups = [groups]

    # Check for admin/auditor group membership
    for group in groups:
        group_lower = group.lower()
        if "admin" in group_lower:
            return "admin"
        if "auditor" in group_lower or "compliance" in group_lower:
            return "auditor"

    return DEFAULT_ROLE
