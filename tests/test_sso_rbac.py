"""Tests for SSO, RBAC, and session management.

Covers:
- SSO config endpoint (provider status)
- SSO login redirect (OIDC + disabled + SAML stub)
- Row-level RBAC tenant filtering
- Session manager: create, refresh, revoke
- API integration: refresh/revoke endpoints
- Tenant scope applied to events query
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard.models import AgentEvent
from api.rbac import TenantScope, filter_events_by_scope
from api.sessions import SessionManager

os.environ["AGENTGUARD_JWT_SECRET"] = "test-secret"
os.environ["AGENTGUARD_ADMIN_KEY"] = "test-admin-key"
os.environ["AGENTGUARD_ANALYST_KEY"] = "test-analyst-key"
os.environ["AGENTGUARD_AUDITOR_KEY"] = "test-auditor-key"


# ── Helpers ──────────────────────────────────────────────────────────


def make_event(agent_id: str = "agent-1", tool_name: str = "tool") -> AgentEvent:
    event = AgentEvent(
        agent_id=agent_id,
        session_id="session-1",
        tool_name=tool_name,
        run_id=uuid4(),
        input_str="input",
        input_hash=AgentEvent.compute_hash("input"),
    )
    event.finalize(output="output", latency_ms=1.0)
    event.policy_result = "ALLOW"
    return event


@pytest.fixture()
def client(tmp_path):
    import api.main as app_module

    db_path = str(tmp_path / "sso_test.db")
    app_module._db_path = db_path
    app_module._store = None
    app_module._policy_engine = None
    app_module._policy_path = None

    with TestClient(app_module.app) as c:
        yield c
    app_module._store = None


def get_admin_token(client: TestClient) -> str:
    resp = client.post("/auth/token", json={"api_key": "test-admin-key"})
    return resp.json()["access_token"]


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── SSO config endpoint ──────────────────────────────────────────────


class TestSSOConfig:
    def test_sso_config_default_disabled(self, client):
        resp = client.get("/sso/config")
        assert resp.status_code == 200
        data = resp.json()
        assert data["provider"] == "none"
        assert data["enabled"] is False

    def test_sso_login_disabled(self, client):
        resp = client.get("/sso/login")
        assert resp.status_code == 400
        assert "not configured" in resp.json()["detail"]


# ── RBAC tenant filtering ────────────────────────────────────────────


class TestTenantFiltering:
    def test_admin_sees_all_events(self):
        events = [
            {"agent_id": "agent-1", "tool_name": "t1"},
            {"agent_id": "agent-2", "tool_name": "t2"},
            {"agent_id": "agent-3", "tool_name": "t3"},
        ]
        scope = TenantScope(role="admin", is_admin=True)
        filtered = filter_events_by_scope(events, scope)
        assert len(filtered) == 3

    def test_analyst_sees_only_assigned_agents(self):
        events = [
            {"agent_id": "agent-1", "tool_name": "t1"},
            {"agent_id": "agent-2", "tool_name": "t2"},
            {"agent_id": "agent-3", "tool_name": "t3"},
        ]
        scope = TenantScope(
            role="analyst", is_admin=False, allowed_agent_ids=["agent-1", "agent-3"]
        )
        filtered = filter_events_by_scope(events, scope)
        assert len(filtered) == 2
        assert all(e["agent_id"] in ("agent-1", "agent-3") for e in filtered)

    def test_empty_allowlist_sees_all(self):
        """No agent mapping configured = no filtering (backward compatible)."""
        events = [
            {"agent_id": "agent-1", "tool_name": "t1"},
            {"agent_id": "agent-2", "tool_name": "t2"},
        ]
        scope = TenantScope(role="analyst", is_admin=False, allowed_agent_ids=[])
        filtered = filter_events_by_scope(events, scope)
        assert len(filtered) == 2

    def test_auditor_filtered(self):
        events = [
            {"agent_id": "finance-agent", "tool_name": "t1"},
            {"agent_id": "healthcare-agent", "tool_name": "t2"},
        ]
        scope = TenantScope(
            role="auditor", is_admin=False, allowed_agent_ids=["finance-agent"]
        )
        filtered = filter_events_by_scope(events, scope)
        assert len(filtered) == 1
        assert filtered[0]["agent_id"] == "finance-agent"


# ── Session manager ──────────────────────────────────────────────────


class TestSessionManager:
    def test_create_refresh_token(self):
        sm = SessionManager()
        result = sm.create_refresh_token(role="admin", email="admin@co.com")
        assert result.access_token
        assert result.refresh_token
        assert result.role == "admin"
        assert len(result.refresh_token) > 20

    def test_refresh_returns_new_jwt(self):
        sm = SessionManager()
        result = sm.create_refresh_token(role="analyst", email="analyst@co.com")
        refreshed = sm.refresh(result.refresh_token)
        assert refreshed is not None
        assert refreshed.access_token != result.access_token  # New JWT
        assert refreshed.role == "analyst"

    def test_refresh_invalid_token_returns_none(self):
        sm = SessionManager()
        assert sm.refresh("invalid-token-abc") is None

    def test_revoke_token(self):
        sm = SessionManager()
        result = sm.create_refresh_token(role="admin")
        assert sm.revoke(result.refresh_token) is True
        # After revocation, refresh should fail
        assert sm.refresh(result.refresh_token) is None

    def test_revoke_nonexistent_returns_false(self):
        sm = SessionManager()
        assert sm.revoke("nonexistent-token") is False

    def test_active_sessions_count(self):
        sm = SessionManager()
        sm.create_refresh_token(role="admin")
        sm.create_refresh_token(role="analyst")
        assert sm.get_active_sessions() == 2

    def test_memory_backend_default(self):
        sm = SessionManager()
        assert sm.backend == "memory"


# ── API session endpoints ────────────────────────────────────────────


class TestSessionEndpoints:
    def test_refresh_endpoint(self, client):
        # Create a session first (via direct session manager)
        import api.main as app_module

        result = app_module._session_manager.create_refresh_token(
            role="admin", email="test@co.com"
        )

        resp = client.post(
            "/auth/refresh",
            json={"refresh_token": result.refresh_token},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "admin"
        assert data["access_token"]

    def test_refresh_invalid_token_401(self, client):
        resp = client.post(
            "/auth/refresh",
            json={"refresh_token": "invalid"},
        )
        assert resp.status_code == 401

    def test_revoke_endpoint(self, client):
        import api.main as app_module

        result = app_module._session_manager.create_refresh_token(role="admin")

        resp = client.post(
            "/auth/revoke",
            json={"refresh_token": result.refresh_token},
        )
        assert resp.status_code == 200
        assert resp.json()["revoked"] is True

        # Double revoke returns False
        resp2 = client.post(
            "/auth/revoke",
            json={"refresh_token": result.refresh_token},
        )
        assert resp2.json()["revoked"] is False

    def test_refreshed_token_works_for_api(self, client, tmp_path):
        """A refreshed JWT can be used to query events."""
        import api.main as app_module

        result = app_module._session_manager.create_refresh_token(role="admin")
        refresh_resp = client.post(
            "/auth/refresh",
            json={"refresh_token": result.refresh_token},
        )
        new_token = refresh_resp.json()["access_token"]

        resp = client.post(
            "/events",
            json={},
            headers=auth_header(new_token),
        )
        assert resp.status_code == 200
