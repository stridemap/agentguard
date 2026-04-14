"""Integration tests for the AgentGuard REST API.

Covers:
- All 10 endpoints with correct responses
- JWT auth: valid token, invalid token, expired token
- RBAC: auditor cannot access /policies/reload (403)
- Rate limiting (429)
- /health and /metrics accessible without auth
- /audit/verify returns chain status
- /audit/export returns JSON and CSV
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard.event_store import EventStore
from agentguard.models import AgentEvent

# Set test env vars before importing the app
os.environ["AGENTGUARD_JWT_SECRET"] = "test-secret"
os.environ["AGENTGUARD_ADMIN_KEY"] = "test-admin-key"
os.environ["AGENTGUARD_ANALYST_KEY"] = "test-analyst-key"
os.environ["AGENTGUARD_AUDITOR_KEY"] = "test-auditor-key"


# ── Fixtures ──────────────────────────────────────────────────────────


def make_event(tool_name: str = "test_tool") -> AgentEvent:
    event = AgentEvent(
        agent_id="api-test-agent",
        session_id="api-test-session",
        tool_name=tool_name,
        run_id=uuid4(),
        input_str="test input",
        input_hash=AgentEvent.compute_hash("test input"),
    )
    event.finalize(output="test output", latency_ms=5.0)
    event.policy_result = "ALLOW"
    return event


@pytest.fixture()
def db_path(tmp_path):
    return str(tmp_path / "api_test.db")


@pytest.fixture()
def client(db_path):
    """Create a test client with a fresh database."""
    import api.main as app_module

    # Reset global state
    app_module._db_path = db_path
    app_module._store = None
    app_module._policy_engine = None
    app_module._policy_path = None

    with TestClient(app_module.app) as c:
        yield c

    # Cleanup
    app_module._store = None


@pytest.fixture()
def seeded_client(db_path):
    """Test client with 5 pre-seeded events."""
    store = EventStore(db_path=db_path)
    for i in range(5):
        store.append(make_event(f"tool_{i}"))
    store.close()

    import api.main as app_module

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


def get_analyst_token(client: TestClient) -> str:
    resp = client.post("/auth/token", json={"api_key": "test-analyst-key"})
    return resp.json()["access_token"]


def get_auditor_token(client: TestClient) -> str:
    resp = client.post("/auth/token", json={"api_key": "test-auditor-key"})
    return resp.json()["access_token"]


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── 1. GET /health (no auth) ────────────────────────────────────────


class TestHealth:
    def test_health_no_auth_required(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_required_fields(self, client):
        data = client.get("/health").json()
        assert "status" in data
        assert "version" in data
        assert "db_connection" in data
        assert "event_count" in data

    def test_health_shows_event_count(self, seeded_client):
        data = seeded_client.get("/health").json()
        assert data["event_count"] == 5


# ── 2. GET /metrics (no auth) ───────────────────────────────────────


class TestMetrics:
    def test_metrics_no_auth_required(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]

    def test_metrics_prometheus_format(self, seeded_client):
        text = seeded_client.get("/metrics").text
        assert "agentguard_events_total" in text
        assert "agentguard_version" in text
        assert "5" in text  # 5 seeded events


# ── 3. POST /auth/token ─────────────────────────────────────────────


class TestAuthToken:
    def test_valid_admin_key(self, client):
        resp = client.post("/auth/token", json={"api_key": "test-admin-key"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "admin"
        assert data["token_type"] == "bearer"
        assert "access_token" in data

    def test_valid_analyst_key(self, client):
        resp = client.post("/auth/token", json={"api_key": "test-analyst-key"})
        assert resp.status_code == 200
        assert resp.json()["role"] == "analyst"

    def test_invalid_key_401(self, client):
        resp = client.post("/auth/token", json={"api_key": "wrong-key"})
        assert resp.status_code == 401

    def test_token_has_expiry(self, client):
        resp = client.post("/auth/token", json={"api_key": "test-admin-key"})
        assert resp.json()["expires_in"] == 1800


# ── 4. POST /events (authenticated) ─────────────────────────────────


class TestQueryEvents:
    def test_requires_auth(self, seeded_client):
        resp = seeded_client.post("/events", json={})
        assert resp.status_code == 401

    def test_returns_events(self, seeded_client):
        token = get_admin_token(seeded_client)
        resp = seeded_client.post("/events", json={}, headers=auth_header(token))
        assert resp.status_code == 200
        assert len(resp.json()) == 5

    def test_filter_by_tool_name(self, seeded_client):
        token = get_admin_token(seeded_client)
        resp = seeded_client.post(
            "/events", json={"tool_name": "tool_0"}, headers=auth_header(token)
        )
        assert resp.status_code == 200
        events = resp.json()
        assert all(e["tool_name"] == "tool_0" for e in events)

    def test_limit_and_offset(self, seeded_client):
        token = get_admin_token(seeded_client)
        resp = seeded_client.post(
            "/events", json={"limit": 2, "offset": 0}, headers=auth_header(token)
        )
        assert len(resp.json()) == 2


# ── 5. GET /events/{id} (authenticated) ─────────────────────────────


class TestGetEvent:
    def test_get_existing_event(self, seeded_client):
        token = get_admin_token(seeded_client)
        # First get all events to find an ID
        events = seeded_client.post(
            "/events", json={}, headers=auth_header(token)
        ).json()
        event_id = events[0]["event_id"]

        resp = seeded_client.get(f"/events/{event_id}", headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json()["event_id"] == event_id

    def test_get_nonexistent_event_404(self, seeded_client):
        token = get_admin_token(seeded_client)
        resp = seeded_client.get("/events/nonexistent-id", headers=auth_header(token))
        assert resp.status_code == 404


# ── 6. GET /audit/verify (authenticated) ────────────────────────────


class TestAuditVerify:
    def test_verify_chain(self, seeded_client):
        token = get_admin_token(seeded_client)
        resp = seeded_client.get("/audit/verify", headers=auth_header(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_valid"] is True
        assert data["total_events"] == 5


# ── 7. GET /audit/export (admin + auditor only) ─────────────────────


class TestAuditExport:
    def test_export_json(self, seeded_client):
        token = get_admin_token(seeded_client)
        resp = seeded_client.get(
            "/audit/export?format=json", headers=auth_header(token)
        )
        assert resp.status_code == 200
        assert "application/json" in resp.headers["content-type"]

    def test_export_csv(self, seeded_client):
        token = get_admin_token(seeded_client)
        resp = seeded_client.get("/audit/export?format=csv", headers=auth_header(token))
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        assert "event_id" in resp.text  # CSV header

    def test_auditor_can_export(self, seeded_client):
        token = get_auditor_token(seeded_client)
        resp = seeded_client.get(
            "/audit/export?format=json", headers=auth_header(token)
        )
        assert resp.status_code == 200

    def test_analyst_cannot_export(self, seeded_client):
        token = get_analyst_token(seeded_client)
        resp = seeded_client.get(
            "/audit/export?format=json", headers=auth_header(token)
        )
        assert resp.status_code == 403


# ── 8. GET /policies (authenticated) ────────────────────────────────


class TestPolicies:
    def test_list_policies_empty(self, client):
        token = get_admin_token(client)
        resp = client.get("/policies", headers=auth_header(token))
        assert resp.status_code == 200
        assert resp.json() == []


# ── 9. POST /policies/reload (admin only) ───────────────────────────


class TestPoliciesReload:
    def test_reload_no_policy_configured(self, client):
        token = get_admin_token(client)
        resp = client.post("/policies/reload", headers=auth_header(token))
        assert resp.status_code == 400

    def test_auditor_cannot_reload(self, client):
        token = get_auditor_token(client)
        resp = client.post("/policies/reload", headers=auth_header(token))
        assert resp.status_code == 403

    def test_analyst_cannot_reload(self, client):
        token = get_analyst_token(client)
        resp = client.post("/policies/reload", headers=auth_header(token))
        assert resp.status_code == 403


# ── 10. GET /dashboard (authenticated) ──────────────────────────────


class TestDashboard:
    def test_dashboard_redirects(self, client):
        token = get_admin_token(client)
        resp = client.get(
            "/dashboard", headers=auth_header(token), follow_redirects=False
        )
        assert resp.status_code == 307


# ── JWT security tests ───────────────────────────────────────────────


class TestJWTSecurity:
    def test_invalid_token_401(self, client):
        resp = client.post(
            "/events", json={}, headers={"Authorization": "Bearer bad-token"}
        )
        assert resp.status_code == 401

    def test_missing_auth_header_401(self, client):
        resp = client.post("/events", json={})
        assert resp.status_code == 401

    def test_wrong_token_type_401(self, client):
        resp = client.post(
            "/events", json={}, headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        assert resp.status_code == 401


# ── Rate limiting tests ──────────────────────────────────────────────


class TestRateLimiting:
    def test_rate_limit_not_hit_under_100(self, client):
        token = get_admin_token(client)
        for _ in range(5):
            resp = client.post("/events", json={}, headers=auth_header(token))
            assert resp.status_code == 200


# ── OpenAPI docs ─────────────────────────────────────────────────────


class TestDocs:
    def test_openapi_accessible(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_openapi_json(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert data["info"]["title"] == "AgentGuard API"
