"""Row-level RBAC for multi-tenant event filtering.

Enforces that users can only see events belonging to their authorized
scope. Admin sees all; analyst/auditor see events for their assigned
agent_ids only.

Tenant isolation is enforced at the API layer — the EventStore query
is filtered by the user's authorized scope before results are returned.

Usage:
    from api.rbac import TenantScope, get_tenant_scope

    scope = get_tenant_scope(user)
    events = filter_events_by_scope(events, scope)
"""

from __future__ import annotations

import os
from typing import Annotated, Any

from fastapi import Depends
from pydantic import BaseModel, Field

from api.auth import TokenPayload, get_current_user

# ── Tenant scope model ───────────────────────────────────────────────

# Configurable role → agent_id mapping via env or config
# Format: "role:agent1,agent2;role:agent3,agent4"
_ROLE_AGENT_MAP_RAW = os.environ.get("AGENTGUARD_ROLE_AGENT_MAP", "")


def _parse_role_agent_map(raw: str) -> dict[str, list[str]]:
    """Parse AGENTGUARD_ROLE_AGENT_MAP env var."""
    mapping: dict[str, list[str]] = {}
    if not raw:
        return mapping
    for entry in raw.split(";"):
        if ":" not in entry:
            continue
        role, agents = entry.split(":", 1)
        mapping[role.strip()] = [a.strip() for a in agents.split(",") if a.strip()]
    return mapping


_ROLE_AGENT_MAP = _parse_role_agent_map(_ROLE_AGENT_MAP_RAW)


class TenantScope(BaseModel):
    """Defines what a user is authorized to see."""

    role: str = Field(description="User's role")
    is_admin: bool = Field(default=False, description="Admin sees everything")
    allowed_agent_ids: list[str] = Field(
        default_factory=list,
        description="Agent IDs this user can see. Empty = all (for admin).",
    )


def get_tenant_scope(
    user: Annotated[TokenPayload, Depends(get_current_user)],
) -> TenantScope:
    """FastAPI dependency: resolve the user's tenant scope from JWT role.

    Admin: sees all events (no filtering).
    Analyst/Auditor: sees only events for their assigned agent_ids.
    If no agent_id mapping is configured, all roles see all events.
    """
    role = user.sub

    if role == "admin":
        return TenantScope(role=role, is_admin=True, allowed_agent_ids=[])

    # Check role → agent_id mapping
    allowed = _ROLE_AGENT_MAP.get(role, [])
    return TenantScope(role=role, is_admin=False, allowed_agent_ids=allowed)


def filter_events_by_scope(
    events: list[dict[str, Any]], scope: TenantScope
) -> list[dict[str, Any]]:
    """Filter events based on the user's tenant scope.

    Admin: no filtering.
    Others: only return events whose agent_id is in allowed_agent_ids.
    If allowed_agent_ids is empty, returns all (no mapping configured).
    """
    if scope.is_admin or not scope.allowed_agent_ids:
        return events

    return [e for e in events if e.get("agent_id") in scope.allowed_agent_ids]
