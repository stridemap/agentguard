"""Tests for compliance reports, retention, and API endpoints.

Covers:
- SOC2 CC6 report generation with auto-populated data
- HIPAA §164.312 report generation
- ISO 27001 A.12.4 report generation
- Data retention: count expired, enforce, dry run
- API compliance endpoints (admin/auditor only)
"""

from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from agentguard.compliance.reports import ComplianceReporter
from agentguard.compliance.retention import RetentionPolicy
from agentguard.event_store import EventStore
from agentguard.models import AgentEvent

os.environ["AGENTGUARD_JWT_SECRET"] = "test-secret"
os.environ["AGENTGUARD_ADMIN_KEY"] = "test-admin-key"
os.environ["AGENTGUARD_ANALYST_KEY"] = "test-analyst-key"
os.environ["AGENTGUARD_AUDITOR_KEY"] = "test-auditor-key"


# ── Helpers ──────────────────────────────────────────────────────────


def make_event(tool_name: str = "tool", policy_result: str = "ALLOW") -> AgentEvent:
    event = AgentEvent(
        agent_id="compliance-test",
        session_id="session-1",
        tool_name=tool_name,
        run_id=uuid4(),
        input_str="input",
        input_hash=AgentEvent.compute_hash("input"),
    )
    event.finalize(output="output", latency_ms=5.0)
    event.policy_result = policy_result
    return event


@pytest.fixture()
def store(tmp_path):
    db_path = str(tmp_path / "compliance.db")
    s = EventStore(db_path=db_path)
    for i in range(10):
        s.append(make_event(f"tool_{i}", "ALLOW" if i < 7 else "BLOCK"))
    yield s
    s.close()


@pytest.fixture()
def client(tmp_path):
    import api.main as app_module

    db_path = str(tmp_path / "api_compliance.db")
    store = EventStore(db_path=db_path)
    for i in range(5):
        store.append(make_event(f"tool_{i}"))
    store.close()

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


def get_auditor_token(client: TestClient) -> str:
    resp = client.post("/auth/token", json={"api_key": "test-auditor-key"})
    return resp.json()["access_token"]


def get_analyst_token(client: TestClient) -> str:
    resp = client.post("/auth/token", json={"api_key": "test-analyst-key"})
    return resp.json()["access_token"]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── SOC2 CC6 Report ──────────────────────────────────────────────────


class TestSOC2Report:
    def test_generate_soc2(self, store):
        reporter = ComplianceReporter(store)
        report = reporter.generate_soc2_cc6()

        assert report["report_type"] == "SOC2 CC6 — Logical Access Controls"
        assert report["framework"] == "AICPA SOC 2 Type II"
        assert "CC6.1" in report["controls"]
        assert "CC6.6" in report["controls"]
        assert "CC6.8" in report["controls"]
        assert report["summary"]["total_events"] == 10
        assert report["summary"]["policy_blocked"] == 3

    def test_soc2_controls_implemented(self, store):
        reporter = ComplianceReporter(store)
        report = reporter.generate_soc2_cc6()
        for ctrl in report["controls"].values():
            assert ctrl["status"] == "IMPLEMENTED"

    def test_soc2_chain_verified(self, store):
        reporter = ComplianceReporter(store)
        report = reporter.generate_soc2_cc6()
        assert report["summary"]["audit_chain_valid"] is True


# ── HIPAA §164.312 Report ────────────────────────────────────────────


class TestHIPAAReport:
    def test_generate_hipaa(self, store):
        reporter = ComplianceReporter(store)
        report = reporter.generate_hipaa_164_312()

        assert "HIPAA" in report["report_type"]
        assert "164.312(a)" in report["safeguards"]
        assert "164.312(b)" in report["safeguards"]
        assert "164.312(c)" in report["safeguards"]
        assert "164.312(d)" in report["safeguards"]
        assert "164.312(e)" in report["safeguards"]

    def test_hipaa_all_implemented(self, store):
        reporter = ComplianceReporter(store)
        report = reporter.generate_hipaa_164_312()
        for safeguard in report["safeguards"].values():
            assert safeguard["status"] == "IMPLEMENTED"


# ── ISO 27001 A.12.4 Report ─────────────────────────────────────────


class TestISO27001Report:
    def test_generate_iso(self, store):
        reporter = ComplianceReporter(store)
        report = reporter.generate_iso27001_a12_4()

        assert "ISO 27001" in report["report_type"]
        assert "A.12.4.1" in report["controls"]
        assert "A.12.4.2" in report["controls"]
        assert "A.12.4.3" in report["controls"]
        assert "A.12.4.4" in report["controls"]

    def test_iso_all_implemented(self, store):
        reporter = ComplianceReporter(store)
        report = reporter.generate_iso27001_a12_4()
        for ctrl in report["controls"].values():
            assert ctrl["status"] == "IMPLEMENTED"


# ── Data Retention ───────────────────────────────────────────────────


class TestRetentionPolicy:
    def test_default_retention(self):
        policy = RetentionPolicy()
        assert policy.days == 30  # RETENTION_PRESETS["default"] = 30

    def test_hipaa_retention(self):
        policy = RetentionPolicy(regulation="hipaa")
        assert policy.days == 365

    def test_soc2_retention(self):
        policy = RetentionPolicy(regulation="soc2")
        assert policy.days == 90

    def test_custom_days(self):
        policy = RetentionPolicy(days=7)
        assert policy.days == 7

    def test_count_expired_none(self, store):
        policy = RetentionPolicy(days=365)
        assert policy.count_expired(store) == 0

    def test_dry_run_does_not_delete(self, store):
        policy = RetentionPolicy(days=365)
        result = policy.enforce(store, dry_run=True)
        assert result["dry_run"] is True
        assert result["deleted_count"] == 0
        assert store.get_event_count() == 10

    def test_status(self, store):
        policy = RetentionPolicy(regulation="hipaa")
        status = policy.status(store)
        assert status["retention_days"] == 365
        assert status["regulation"] == "hipaa"
        assert status["total_events"] == 10


# ── Compliance API Endpoints ─────────────────────────────────────────


class TestComplianceAPI:
    def test_soc2_endpoint(self, client):
        token = get_admin_token(client)
        resp = client.get("/compliance/soc2", headers=auth(token))
        assert resp.status_code == 200
        assert "CC6.1" in resp.json()["controls"]

    def test_hipaa_endpoint(self, client):
        token = get_admin_token(client)
        resp = client.get("/compliance/hipaa", headers=auth(token))
        assert resp.status_code == 200
        assert "164.312(a)" in resp.json()["safeguards"]

    def test_iso27001_endpoint(self, client):
        token = get_admin_token(client)
        resp = client.get("/compliance/iso27001", headers=auth(token))
        assert resp.status_code == 200
        assert "A.12.4.1" in resp.json()["controls"]

    def test_auditor_can_access_reports(self, client):
        token = get_auditor_token(client)
        resp = client.get("/compliance/soc2", headers=auth(token))
        assert resp.status_code == 200

    def test_analyst_cannot_access_reports(self, client):
        token = get_analyst_token(client)
        resp = client.get("/compliance/soc2", headers=auth(token))
        assert resp.status_code == 403

    def test_retention_status_endpoint(self, client):
        token = get_admin_token(client)
        resp = client.get(
            "/compliance/retention/status?regulation=hipaa",
            headers=auth(token),
        )
        assert resp.status_code == 200
        assert resp.json()["retention_days"] == 365

    def test_retention_enforce_dry_run(self, client):
        token = get_admin_token(client)
        resp = client.post(
            "/compliance/retention/enforce?regulation=soc2&dry_run=true",
            headers=auth(token),
        )
        assert resp.status_code == 200
        assert resp.json()["dry_run"] is True
