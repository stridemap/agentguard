"""Tests for multi-tenant SaaS, archival, and billing.

Covers:
- Tenant CRUD (create, get, list, update, suspend, delete)
- Tenant-isolated event stores
- Usage/billing tracking
- S3/local archival
- Tenant API endpoints
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard.archival import AuditArchiver
from agentguard.event_store import EventStore
from agentguard.models import AgentEvent
from agentguard.multi_tenant import TenantManager

os.environ["AGENTGUARD_JWT_SECRET"] = "test-secret"
os.environ["AGENTGUARD_ADMIN_KEY"] = "test-admin-key"


# ── Helpers ──────────────────────────────────────────────────────────


def make_event(agent_id: str = "test-agent") -> AgentEvent:
    event = AgentEvent(
        agent_id=agent_id,
        session_id="s1",
        tool_name="tool",
        run_id=uuid4(),
        input_str="input",
        input_hash=AgentEvent.compute_hash("input"),
    )
    event.finalize(output="output", latency_ms=1.0)
    event.policy_result = "ALLOW"
    return event


@pytest.fixture()
def tm(tmp_path):
    return TenantManager(base_path=str(tmp_path / "tenants"))


@pytest.fixture()
def client(tmp_path):
    import api.main as app_module
    import api.tenants as tenants_module

    app_module._db_path = str(tmp_path / "mt.db")
    app_module._store = None
    app_module._policy_engine = None
    tenants_module._tenant_manager = TenantManager(base_path=str(tmp_path / "tenants"))

    with TestClient(app_module.app) as c:
        yield c
    app_module._store = None


def get_admin_token(client: TestClient) -> str:
    return client.post("/auth/token", json={"api_key": "test-admin-key"}).json()[
        "access_token"
    ]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Tenant Manager ───────────────────────────────────────────────────


class TestTenantManager:
    def test_create_tenant(self, tm):
        tenant = tm.create_tenant(name="Acme Corp", admin_email="admin@acme.com")
        assert tenant.name == "Acme Corp"
        assert tenant.status == "active"
        assert len(tenant.tenant_id) == 8

    def test_get_tenant(self, tm):
        t = tm.create_tenant(name="Test")
        assert tm.get_tenant(t.tenant_id) is not None

    def test_list_tenants(self, tm):
        tm.create_tenant(name="A")
        tm.create_tenant(name="B")
        assert len(tm.list_tenants()) == 2

    def test_update_tenant(self, tm):
        t = tm.create_tenant(name="Old Name")
        updated = tm.update_tenant(t.tenant_id, name="New Name")
        assert updated.name == "New Name"

    def test_suspend_tenant(self, tm):
        t = tm.create_tenant(name="Suspend Me")
        assert tm.suspend_tenant(t.tenant_id) is True
        assert tm.get_tenant(t.tenant_id).status == "suspended"

    def test_delete_tenant(self, tm):
        t = tm.create_tenant(name="Delete Me")
        assert tm.delete_tenant(t.tenant_id) is True
        assert tm.get_tenant(t.tenant_id).status == "deleted"

    def test_nonexistent_tenant(self, tm):
        assert tm.get_tenant("missing") is None
        assert tm.suspend_tenant("missing") is False


# ── Tenant Isolation ─────────────────────────────────────────────────


class TestTenantIsolation:
    def test_isolated_stores(self, tm):
        t1 = tm.create_tenant(name="Tenant 1")
        t2 = tm.create_tenant(name="Tenant 2")

        store1 = tm.get_tenant_store(t1.tenant_id)
        store2 = tm.get_tenant_store(t2.tenant_id)

        store1.append(make_event("t1-agent"))
        store1.append(make_event("t1-agent"))
        store2.append(make_event("t2-agent"))

        assert store1.get_event_count() == 2
        assert store2.get_event_count() == 1

    def test_tenant_store_creates_on_demand(self, tm):
        t = tm.create_tenant(name="Lazy")
        store = tm.get_tenant_store(t.tenant_id)
        assert store is not None
        assert store.get_event_count() == 0


# ── Usage / Billing ──────────────────────────────────────────────────


class TestBilling:
    def test_record_usage(self, tm):
        t = tm.create_tenant(name="Billing Test")
        tm.record_usage(t.tenant_id, events=100, api_calls=50)
        usage = tm.get_usage(t.tenant_id)
        assert usage.event_count == 100
        assert usage.api_calls == 50

    def test_cumulative_usage(self, tm):
        t = tm.create_tenant(name="Cumulative")
        tm.record_usage(t.tenant_id, events=50)
        tm.record_usage(t.tenant_id, events=30)
        assert tm.get_usage(t.tenant_id).event_count == 80

    def test_stats(self, tm):
        tm.create_tenant(name="A")
        tm.create_tenant(name="B")
        stats = tm.stats()
        assert stats["total_tenants"] == 2
        assert stats["active_tenants"] == 2


# ── Archival ─────────────────────────────────────────────────────────


class TestArchival:
    def test_local_archive(self, tmp_path):
        store = EventStore(db_path=str(tmp_path / "archive.db"))
        for _ in range(5):
            store.append(make_event())

        archiver = AuditArchiver(backend="local", bucket=str(tmp_path / "archive"))
        result = archiver.archive(store)

        assert result["status"] == "archived"
        assert result["event_count"] == 5
        assert Path(result["file_path"]).exists()

        # Verify archive content
        content = json.loads(Path(result["file_path"]).read_text())
        assert content["event_count"] == 5
        assert content["chain_verification"]["is_valid"] is True
        store.close()

    def test_archive_empty_store(self, tmp_path):
        store = EventStore(db_path=str(tmp_path / "empty.db"))
        archiver = AuditArchiver(backend="local", bucket=str(tmp_path / "archive"))
        result = archiver.archive(store)
        assert result["status"] == "skipped"
        store.close()

    def test_s3_without_boto3(self, tmp_path):
        """S3 archival fails gracefully without boto3."""
        store = EventStore(db_path=str(tmp_path / "s3.db"))
        store.append(make_event())
        archiver = AuditArchiver(backend="s3", bucket="test-bucket")
        result = archiver.archive(store)
        # May fail with ImportError or connection error — both are "error"
        assert result["status"] in ("error", "archived")
        store.close()


# ── Tenant API ───────────────────────────────────────────────────────


class TestTenantAPI:
    def test_create_tenant_api(self, client):
        token = get_admin_token(client)
        resp = client.post(
            "/tenants",
            json={"name": "API Tenant", "admin_email": "admin@test.com"},
            headers=auth(token),
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "API Tenant"

    def test_list_tenants_api(self, client):
        token = get_admin_token(client)
        client.post("/tenants", json={"name": "T1"}, headers=auth(token))
        client.post("/tenants", json={"name": "T2"}, headers=auth(token))

        resp = client.get("/tenants", headers=auth(token))
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_get_tenant_api(self, client):
        token = get_admin_token(client)
        t = client.post("/tenants", json={"name": "Get Me"}, headers=auth(token)).json()

        resp = client.get(f"/tenants/{t['tenant_id']}", headers=auth(token))
        assert resp.status_code == 200
        assert resp.json()["name"] == "Get Me"

    def test_suspend_tenant_api(self, client):
        token = get_admin_token(client)
        t = client.post(
            "/tenants", json={"name": "Suspend"}, headers=auth(token)
        ).json()

        resp = client.post(f"/tenants/{t['tenant_id']}/suspend", headers=auth(token))
        assert resp.status_code == 200
        assert resp.json()["status"] == "suspended"

    def test_usage_api(self, client):
        token = get_admin_token(client)
        t = client.post("/tenants", json={"name": "Usage"}, headers=auth(token)).json()

        resp = client.get(f"/tenants/{t['tenant_id']}/usage", headers=auth(token))
        assert resp.status_code == 200
        assert resp.json()["event_count"] == 0

    def test_stats_api(self, client):
        token = get_admin_token(client)
        resp = client.get("/tenants/admin/stats", headers=auth(token))
        assert resp.status_code == 200
        assert "total_tenants" in resp.json()
