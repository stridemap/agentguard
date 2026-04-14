"""Policy marketplace API endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from agentguard.marketplace import PolicyMarketplace
from api.auth import TokenPayload, require_role
from api.rate_limit import check_rate_limit

router = APIRouter(prefix="/marketplace", tags=["Marketplace"])

_marketplace = PolicyMarketplace()


@router.get("/packs")
def list_packs(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> list[dict[str, Any]]:
    """List all available policy packs."""
    return _marketplace.list_packs()


@router.get("/industries")
def list_industries(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> list[str]:
    """List available industry verticals."""
    return _marketplace.list_industries()


@router.get("/search")
def search_packs(
    q: str = Query(description="Search keyword"),
    _user: Annotated[TokenPayload, Depends(check_rate_limit)] = None,
) -> list[dict[str, Any]]:
    """Search policy packs by keyword."""
    return _marketplace.search(q)


@router.get("/packs/{industry}/{pack_name}")
def get_pack(
    industry: str,
    pack_name: str,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> dict[str, Any]:
    """Get details and rules for a specific policy pack."""
    pack = _marketplace.get_pack(f"{industry}/{pack_name}")
    if pack is None:
        return {"error": f"Pack not found: {industry}/{pack_name}"}
    return {
        **pack.preview(),
        "rules": pack.rules(),
    }


@router.post("/install/{industry}/{pack_name}")
def install_pack(
    industry: str,
    pack_name: str,
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, Any]:
    """Install a policy pack (admin only)."""
    return _marketplace.install_pack(f"{industry}/{pack_name}")
