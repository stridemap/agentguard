"""Multi-tenant API endpoints — organization management and billing.

Admin-only endpoints for tenant lifecycle, usage tracking, and archival.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agentguard.archival import AuditArchiver
from agentguard.multi_tenant import TenantManager
from api.auth import TokenPayload, require_role
from api.rate_limit import check_rate_limit

router = APIRouter(prefix="/tenants", tags=["Tenants"])

_tenant_manager = TenantManager()
_archiver = AuditArchiver()


# ── Request models ───────────────────────────────────────────────────


class CreateTenantRequest(BaseModel):
    name: str
    admin_email: str = ""
    plan: str = Field(default="free", pattern="^(free|pro|enterprise)$")
    settings: dict[str, Any] = Field(default_factory=dict)


class UpdateTenantRequest(BaseModel):
    name: str | None = None
    plan: str | None = None
    status: str | None = None


# ── Endpoints ────────────────────────────────────────────────────────


@router.post("")
def create_tenant(
    request: CreateTenantRequest,
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, Any]:
    """Create a new tenant organization (admin only)."""
    tenant = _tenant_manager.create_tenant(
        name=request.name,
        admin_email=request.admin_email,
        plan=request.plan,
        settings=request.settings or None,
    )
    return tenant.model_dump()


@router.get("")
def list_tenants(
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> list[dict[str, Any]]:
    """List all tenants."""
    return [t.model_dump() for t in _tenant_manager.list_tenants()]


@router.get("/{tenant_id}")
def get_tenant(
    tenant_id: str,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> dict[str, Any]:
    """Get tenant details."""
    tenant = _tenant_manager.get_tenant(tenant_id)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant.model_dump()


@router.patch("/{tenant_id}")
def update_tenant(
    tenant_id: str,
    request: UpdateTenantRequest,
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, Any]:
    """Update tenant (admin only)."""
    updates = {k: v for k, v in request.model_dump().items() if v is not None}
    tenant = _tenant_manager.update_tenant(tenant_id, **updates)
    if tenant is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return tenant.model_dump()


@router.post("/{tenant_id}/suspend")
def suspend_tenant(
    tenant_id: str,
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, str]:
    """Suspend a tenant (admin only)."""
    if not _tenant_manager.suspend_tenant(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"status": "suspended", "tenant_id": tenant_id}


@router.delete("/{tenant_id}")
def delete_tenant(
    tenant_id: str,
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, str]:
    """Delete a tenant (admin only)."""
    if not _tenant_manager.delete_tenant(tenant_id):
        raise HTTPException(status_code=404, detail="Tenant not found")
    return {"status": "deleted", "tenant_id": tenant_id}


# ── Usage / Billing ──────────────────────────────────────────────────


@router.get("/{tenant_id}/usage")
def get_tenant_usage(
    tenant_id: str,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> dict[str, Any]:
    """Get usage metrics for a tenant."""
    usage = _tenant_manager.get_usage(tenant_id)
    if usage is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return usage.model_dump()


@router.get("/admin/usage")
def get_all_usage(
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> list[dict[str, Any]]:
    """Get usage for all tenants (admin only)."""
    return [u.model_dump() for u in _tenant_manager.get_all_usage()]


@router.get("/admin/stats")
def tenant_stats(
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, Any]:
    """Get tenant platform stats (admin only)."""
    return _tenant_manager.stats()


# ── Archival ─────────────────────────────────────────────────────────


@router.post("/{tenant_id}/archive")
def archive_tenant_events(
    tenant_id: str,
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, Any]:
    """Archive a tenant's events to cloud storage (admin only)."""
    store = _tenant_manager.get_tenant_store(tenant_id)
    if store is None:
        raise HTTPException(status_code=404, detail="Tenant not found")
    return _archiver.archive(store)
