"""Federation API endpoints for multi-agent governance.

Provides agent registration, session tracking, call graph visualization,
and federation policy management. Requires admin or analyst role.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from agentguard.federation import FederationManager, FederationRule
from api.auth import TokenPayload, require_role
from api.rate_limit import check_rate_limit

router = APIRouter(prefix="/federation", tags=["Federation"])

_manager = FederationManager()


def get_manager() -> FederationManager:
    return _manager


# ── Request models ───────────────────────────────────────────────────


class RegisterAgentRequest(BaseModel):
    agent_id: str
    cluster: str = "default"
    tools: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CreateSessionRequest(BaseModel):
    initiator: str
    parent_id: str | None = None


class RecordHandoffRequest(BaseModel):
    from_agent: str
    to_agent: str
    tool_name: str = ""
    latency_ms: float = 0.0


class AddRuleRequest(BaseModel):
    id: str
    from_agent: str
    to_agent: str
    action: str = "ALLOW"
    conditions: dict[str, Any] = Field(default_factory=dict)


# ── Endpoints ────────────────────────────────────────────────────────


@router.post("/agents")
def register_agent(
    request: RegisterAgentRequest,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Register an agent in the federation."""
    fm = get_manager()
    node = fm.register_agent(
        agent_id=request.agent_id,
        cluster=request.cluster,
        tools=request.tools,
        metadata=request.metadata,
    )
    return node.model_dump()


@router.get("/agents")
def list_agents(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """List all registered agents."""
    fm = get_manager()
    return [a.model_dump() for a in fm.list_agents()]


@router.post("/sessions")
def create_session(
    request: CreateSessionRequest,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Create a distributed trace session."""
    fm = get_manager()
    session = fm.create_session(
        initiator=request.initiator,
        parent_id=request.parent_id,
    )
    return session.model_dump()


@router.get("/sessions")
def list_sessions(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
    status_filter: str | None = None,
):
    """List trace sessions, optionally filtered by status."""
    fm = get_manager()
    return [s.model_dump() for s in fm.list_sessions(status=status_filter)]


@router.get("/sessions/{trace_id}")
def get_session(
    trace_id: str,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Get a specific trace session."""
    fm = get_manager()
    session = fm.get_session(trace_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.model_dump()


@router.post("/sessions/{trace_id}/handoff")
def record_handoff(
    trace_id: str,
    request: RecordHandoffRequest,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Record an agent-to-agent handoff."""
    fm = get_manager()
    handoff = fm.record_handoff(
        trace_id=trace_id,
        from_agent=request.from_agent,
        to_agent=request.to_agent,
        tool_name=request.tool_name,
        latency_ms=request.latency_ms,
    )
    if handoff is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return handoff.model_dump()


@router.post("/sessions/{trace_id}/complete")
def complete_session(
    trace_id: str,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Mark a session as completed."""
    fm = get_manager()
    if not fm.complete_session(trace_id):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "completed", "trace_id": trace_id}


@router.get("/sessions/{trace_id}/graph")
def get_call_graph(
    trace_id: str,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Get the directed call graph for a session."""
    fm = get_manager()
    graph = fm.get_call_graph(trace_id)
    if graph is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return graph


@router.post("/rules")
def add_federation_rule(
    request: AddRuleRequest,
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
):
    """Add a federation policy rule (admin only)."""
    fm = get_manager()
    rule = FederationRule(
        id=request.id,
        from_agent=request.from_agent,
        to_agent=request.to_agent,
        action=request.action,
        conditions=request.conditions,
    )
    fm.add_rule(rule)
    return {"status": "added", "rule_id": rule.id}


@router.get("/rules")
def list_federation_rules(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """List all federation policy rules."""
    fm = get_manager()
    return [r.model_dump() for r in fm._rules]


@router.get("/stats")
def federation_stats(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Get federation statistics."""
    fm = get_manager()
    return fm.stats()
