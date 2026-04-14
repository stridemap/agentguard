"""AgentGuard REST API — production-grade FastAPI application.

10 endpoints wrapping the AgentGuard core library:

Public (no auth):
  GET  /health          — system health status
  GET  /metrics         — Prometheus-compatible text metrics

Authenticated (JWT Bearer):
  POST /auth/token      — exchange API key for JWT
  POST /events          — query events with filters
  GET  /events/{id}     — get single event by ID
  GET  /audit/verify    — verify audit chain integrity
  GET  /audit/export    — export events as JSON or CSV
  GET  /policies        — list loaded policy rules
  POST /policies/reload — trigger policy hot-reload (admin only)
  GET  /dashboard       — redirect to Streamlit dashboard

Run:
  uvicorn api.main:app --reload
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel, Field

from agentguard import __version__
from agentguard.event_store import EventStore
from agentguard.policy_engine import PolicyEngine
from api.auth import (
    API_KEYS,
    TokenPayload,
    TokenRequest,
    TokenResponse,
    create_token,
    require_role,
)
from api.rate_limit import check_rate_limit

# ── App ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="AgentGuard API",
    description="Governance REST API for LLM-powered AI agents",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── SSO router ───────────────────────────────────────────────────────

from api.compliance import router as compliance_router  # noqa: E402
from api.federation import router as federation_router  # noqa: E402
from api.marketplace import router as marketplace_router  # noqa: E402
from api.rbac import TenantScope, filter_events_by_scope, get_tenant_scope  # noqa: E402
from api.sessions import SessionManager  # noqa: E402
from api.sso import router as sso_router  # noqa: E402

app.include_router(sso_router)
app.include_router(compliance_router)
app.include_router(federation_router)
app.include_router(marketplace_router)

_session_manager = SessionManager()

# ── Shared state ─────────────────────────────────────────────────────

_db_path = os.environ.get("DATABASE_URL", "agentguard.db")
_policy_path = os.environ.get("AGENTGUARD_POLICY_PATH", None)
_dashboard_url = os.environ.get("AGENTGUARD_DASHBOARD_URL", "http://localhost:8501")

_store: EventStore | None = None
_policy_engine: PolicyEngine | None = None
_metrics_collector = None  # Set externally by interceptor if running in-process


def get_store() -> EventStore:
    global _store
    if _store is None:
        _store = EventStore(db_path=_db_path)
    return _store


def get_policy_engine() -> PolicyEngine | None:
    global _policy_engine
    if _policy_engine is None and _policy_path:
        with contextlib.suppress(Exception):
            _policy_engine = PolicyEngine(_policy_path)
    return _policy_engine


# ── Models ───────────────────────────────────────────────────────────


class EventQuery(BaseModel):
    agent_id: str | None = None
    tool_name: str | None = None
    risk_flag: str | None = None
    policy_result: str | None = None
    time_start: str | None = None
    time_end: str | None = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class ErrorResponse(BaseModel):
    error: str
    message: str
    trace_id: str | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    db_connection: str
    event_count: int
    policy_rules: int


# ── 1. GET /health (no auth) ────────────────────────────────────────


@app.get("/health", response_model=HealthResponse, tags=["System"])
def health():
    """System health: DB connection, event count, version."""
    store = get_store()
    store_health = store.health_check()
    engine = get_policy_engine()

    return HealthResponse(
        status=store_health.get("status", "unknown"),
        version=__version__,
        db_connection=store_health.get("status", "unknown"),
        event_count=store_health.get("event_count", 0),
        policy_rules=engine.get_rule_count() if engine else 0,
    )


# ── 2. GET /metrics (no auth) ───────────────────────────────────────


@app.get("/metrics", response_class=PlainTextResponse, tags=["System"])
def metrics():
    """Prometheus-compatible text/plain metrics (5 core metrics + version + uptime)."""

    # Use global metrics collector if available, else basic fallback
    if _metrics_collector is not None:
        return _metrics_collector.render(version=__version__)

    store = get_store()
    count = store.get_event_count()

    lines = [
        "# HELP agentguard_events_total Total events in the store",
        "# TYPE agentguard_events_total counter",
        f"agentguard_events_total {count}",
        "",
        "# HELP agentguard_version AgentGuard version info",
        "# TYPE agentguard_version gauge",
        f'agentguard_version{{version="{__version__}"}} 1',
        "",
    ]
    return "\n".join(lines)


# ── 3. POST /auth/token ─────────────────────────────────────────────


@app.post("/auth/token", response_model=TokenResponse, tags=["Auth"])
def create_auth_token(request: TokenRequest):
    """Exchange an API key for a JWT (30-min expiry)."""
    role = API_KEYS.get(request.api_key)
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    token = create_token(role)
    return TokenResponse(access_token=token, role=role)


# ── 3b. POST /auth/refresh ──────────────────────────────────────────


class RefreshRequest(BaseModel):
    refresh_token: str


@app.post("/auth/refresh", tags=["Auth"])
def refresh_auth_token(request: RefreshRequest):
    """Exchange a refresh token for a new JWT."""
    result = _session_manager.refresh(request.refresh_token)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return result


# ── 3c. POST /auth/revoke ───────────────────────────────────────────


@app.post("/auth/revoke", tags=["Auth"])
def revoke_token(request: RefreshRequest):
    """Revoke a refresh token (logout)."""
    revoked = _session_manager.revoke(request.refresh_token)
    return {"revoked": revoked}


# ── 4. POST /events (authenticated + tenant-filtered) ────────────────


@app.post("/events", tags=["Events"])
def query_events(
    query: EventQuery,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
    scope: Annotated[TenantScope, Depends(get_tenant_scope)],
) -> list[dict[str, Any]]:
    """Query events with filter parameters + tenant scope filtering."""
    store = get_store()
    events = store.get_events(limit=query.limit, offset=query.offset)

    # Apply tenant scope (row-level RBAC)
    filtered = filter_events_by_scope(events, scope)

    # Apply user filters
    if query.agent_id:
        filtered = [e for e in filtered if e.get("agent_id") == query.agent_id]
    if query.tool_name:
        filtered = [e for e in filtered if e.get("tool_name") == query.tool_name]
    if query.risk_flag:
        filtered = [e for e in filtered if query.risk_flag in e.get("risk_flags", "")]
    if query.policy_result:
        filtered = [
            e for e in filtered if e.get("policy_result") == query.policy_result
        ]
    if query.time_start:
        filtered = [e for e in filtered if e.get("timestamp", "") >= query.time_start]
    if query.time_end:
        filtered = [e for e in filtered if e.get("timestamp", "") <= query.time_end]

    return filtered


# ── 5. GET /events/{event_id} (authenticated) ───────────────────────


@app.get("/events/{event_id}", tags=["Events"])
def get_event(
    event_id: str,
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> dict[str, Any]:
    """Get a single event by ID."""
    store = get_store()
    event = store.get_event(event_id)
    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} not found",
        )
    return event


# ── 6. GET /audit/verify (authenticated) ────────────────────────────


@app.get("/audit/verify", tags=["Audit"])
def verify_audit_chain(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> dict[str, Any]:
    """Verify the cryptographic audit chain integrity."""
    store = get_store()
    return store.verify_chain()


# ── 7. GET /audit/export (authenticated) ────────────────────────────


@app.get("/audit/export", tags=["Audit"])
def export_events(
    format: str = Query(default="json", regex="^(json|csv)$"),
    _user: Annotated[TokenPayload, Depends(require_role("admin", "auditor"))] = None,
):
    """Export events as JSON or CSV."""
    store = get_store()
    events = store.get_events(limit=10000)

    if format == "csv":
        output = io.StringIO()
        if events:
            writer = csv.DictWriter(output, fieldnames=events[0].keys())
            writer.writeheader()
            writer.writerows(events)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=agentguard_events.csv"
            },
        )

    return StreamingResponse(
        iter([json.dumps(events, indent=2, default=str)]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=agentguard_events.json"},
    )


# ── 8. GET /policies (authenticated) ────────────────────────────────


@app.get("/policies", tags=["Policies"])
def list_policies(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
) -> list[dict[str, Any]]:
    """List all loaded policy rules."""
    engine = get_policy_engine()
    if engine is None:
        return []
    return [rule.model_dump() for rule in engine.get_rules()]


# ── 9. POST /policies/reload (admin only) ───────────────────────────


@app.post("/policies/reload", tags=["Policies"])
def reload_policies(
    _user: Annotated[TokenPayload, Depends(require_role("admin"))] = None,
) -> dict[str, str]:
    """Trigger policy hot-reload (admin only)."""
    engine = get_policy_engine()
    if engine is None or engine.policy_path is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No policy file configured",
        )
    engine.load_policies(engine.policy_path)
    return {
        "status": "reloaded",
        "rules": str(engine.get_rule_count()),
        "path": engine.policy_path,
    }


# ── 10. GET /dashboard (authenticated) ──────────────────────────────


@app.get("/dashboard", tags=["System"])
def dashboard(
    _user: Annotated[TokenPayload, Depends(check_rate_limit)],
):
    """Redirect to the Streamlit dashboard."""
    return RedirectResponse(url=_dashboard_url)


# ── Startup / shutdown ───────────────────────────────────────────────


@app.on_event("startup")
def startup():
    """Initialize store and policy engine on startup."""
    get_store()
    get_policy_engine()


@app.on_event("shutdown")
def shutdown():
    """Close database connections on shutdown."""
    global _store
    if _store is not None:
        _store.close()
        _store = None
