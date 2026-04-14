"""Tests for multi-agent federation and cross-system session tracking.

Covers:
- Agent registration and listing
- Distributed session creation and tracking
- Agent-to-agent handoff recording
- Call graph generation
- Federation policy evaluation (ALLOW/BLOCK)
- Session lifecycle (active → completed)
- API endpoints for federation management
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from agentguard.federation import FederationManager, FederationRule

os.environ["AGENTGUARD_JWT_SECRET"] = "test-secret"
os.environ["AGENTGUARD_ADMIN_KEY"] = "test-admin-key"
os.environ["AGENTGUARD_ANALYST_KEY"] = "test-analyst-key"


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def fm():
    return FederationManager()


@pytest.fixture()
def client(tmp_path):
    import api.main as app_module

    app_module._db_path = str(tmp_path / "fed.db")
    app_module._store = None
    app_module._policy_engine = None
    app_module._policy_path = None

    # Reset federation manager
    import api.federation as fed_module

    fed_module._manager = FederationManager()

    with TestClient(app_module.app) as c:
        yield c
    app_module._store = None


def get_admin_token(client: TestClient) -> str:
    return client.post("/auth/token", json={"api_key": "test-admin-key"}).json()[
        "access_token"
    ]


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ── Agent Registry ───────────────────────────────────────────────────


class TestAgentRegistry:
    def test_register_agent(self, fm):
        node = fm.register_agent("email-agent", cluster="us-east")
        assert node.agent_id == "email-agent"
        assert node.cluster == "us-east"

    def test_register_with_tools(self, fm):
        node = fm.register_agent("crm-agent", tools=["query_crm", "update_crm"])
        assert node.tools == ["query_crm", "update_crm"]

    def test_list_agents(self, fm):
        fm.register_agent("a1")
        fm.register_agent("a2")
        fm.register_agent("a3")
        assert len(fm.list_agents()) == 3

    def test_get_agent(self, fm):
        fm.register_agent("test-agent", cluster="eu-west")
        node = fm.get_agent("test-agent")
        assert node is not None
        assert node.cluster == "eu-west"

    def test_get_nonexistent_agent(self, fm):
        assert fm.get_agent("missing") is None


# ── Session Tracking ─────────────────────────────────────────────────


class TestSessionTracking:
    def test_create_session(self, fm):
        session = fm.create_session(initiator="email-agent")
        assert session.initiator == "email-agent"
        assert session.status == "active"
        assert len(session.trace_id) == 32
        assert "email-agent" in session.agents_involved

    def test_create_session_with_parent(self, fm):
        parent = fm.create_session(initiator="orchestrator")
        child = fm.create_session(initiator="sub-agent", parent_id=parent.trace_id)
        assert child.parent_id == parent.trace_id

    def test_get_session(self, fm):
        session = fm.create_session(initiator="agent-1")
        retrieved = fm.get_session(session.trace_id)
        assert retrieved is not None
        assert retrieved.trace_id == session.trace_id

    def test_list_sessions(self, fm):
        fm.create_session(initiator="a1")
        fm.create_session(initiator="a2")
        assert len(fm.list_sessions()) == 2

    def test_list_sessions_by_status(self, fm):
        s1 = fm.create_session(initiator="a1")
        fm.create_session(initiator="a2")
        fm.complete_session(s1.trace_id)
        assert len(fm.list_sessions(status="active")) == 1
        assert len(fm.list_sessions(status="completed")) == 1

    def test_complete_session(self, fm):
        session = fm.create_session(initiator="agent")
        assert fm.complete_session(session.trace_id) is True
        assert fm.get_session(session.trace_id).status == "completed"

    def test_complete_nonexistent(self, fm):
        assert fm.complete_session("missing") is False


# ── Handoff Tracking ─────────────────────────────────────────────────


class TestHandoffTracking:
    def test_record_handoff(self, fm):
        session = fm.create_session(initiator="email-agent")
        handoff = fm.record_handoff(
            session.trace_id, from_agent="email-agent", to_agent="crm-agent"
        )
        assert handoff is not None
        assert handoff.from_agent == "email-agent"
        assert handoff.to_agent == "crm-agent"
        assert handoff.policy_result == "ALLOW"

    def test_handoff_adds_agent(self, fm):
        session = fm.create_session(initiator="a1")
        fm.record_handoff(session.trace_id, "a1", "a2")
        updated = fm.get_session(session.trace_id)
        assert "a2" in updated.agents_involved

    def test_handoff_nonexistent_session(self, fm):
        assert fm.record_handoff("missing", "a1", "a2") is None

    def test_multiple_handoffs(self, fm):
        session = fm.create_session(initiator="orchestrator")
        fm.record_handoff(session.trace_id, "orchestrator", "agent-a")
        fm.record_handoff(session.trace_id, "agent-a", "agent-b")
        fm.record_handoff(session.trace_id, "agent-b", "agent-c")

        updated = fm.get_session(session.trace_id)
        assert len(updated.handoffs) == 3
        assert len(updated.agents_involved) == 4


# ── Call Graph ───────────────────────────────────────────────────────


class TestCallGraph:
    def test_call_graph(self, fm):
        fm.register_agent("a1", cluster="us-east")
        fm.register_agent("a2", cluster="us-east")
        fm.register_agent("a3", cluster="eu-west")

        session = fm.create_session(initiator="a1")
        fm.record_handoff(session.trace_id, "a1", "a2", tool_name="query")
        fm.record_handoff(session.trace_id, "a2", "a3", tool_name="send")

        graph = fm.get_call_graph(session.trace_id)
        assert graph is not None
        assert graph["agent_count"] == 3
        assert graph["handoff_count"] == 2
        assert len(graph["nodes"]) == 3
        assert len(graph["edges"]) == 2

    def test_graph_includes_cluster(self, fm):
        fm.register_agent("agent-1", cluster="prod")
        session = fm.create_session(initiator="agent-1")
        graph = fm.get_call_graph(session.trace_id)
        assert graph["nodes"][0]["cluster"] == "prod"

    def test_graph_nonexistent_session(self, fm):
        assert fm.get_call_graph("missing") is None


# ── Federation Policy ────────────────────────────────────────────────


class TestFederationPolicy:
    def test_default_allow(self, fm):
        result = fm.evaluate_federation("a1", "a2")
        assert result == "ALLOW"

    def test_block_rule(self, fm):
        fm.add_rule(
            FederationRule(
                id="block_cross_cluster",
                from_agent="untrusted-agent",
                to_agent="*",
                action="BLOCK",
            )
        )
        assert fm.evaluate_federation("untrusted-agent", "any-target") == "BLOCK"
        assert fm.evaluate_federation("trusted-agent", "any-target") == "ALLOW"

    def test_wildcard_from(self, fm):
        fm.add_rule(
            FederationRule(
                id="alert_all_to_finance",
                from_agent="*",
                to_agent="finance-agent",
                action="ALERT",
            )
        )
        assert fm.evaluate_federation("any-agent", "finance-agent") == "ALERT"
        assert fm.evaluate_federation("any-agent", "other-agent") == "ALLOW"

    def test_tool_condition(self, fm):
        fm.add_rule(
            FederationRule(
                id="block_delete",
                from_agent="*",
                to_agent="*",
                action="BLOCK",
                conditions={"tool_name": "delete_records"},
            )
        )
        assert fm.evaluate_federation("a1", "a2", tool_name="delete_records") == "BLOCK"
        assert fm.evaluate_federation("a1", "a2", tool_name="read_records") == "ALLOW"

    def test_handoff_applies_policy(self, fm):
        fm.add_rule(
            FederationRule(
                id="block_rogue", from_agent="rogue", to_agent="*", action="BLOCK"
            )
        )
        session = fm.create_session(initiator="rogue")
        handoff = fm.record_handoff(session.trace_id, "rogue", "target")
        assert handoff.policy_result == "BLOCK"


# ── Stats ────────────────────────────────────────────────────────────


class TestFederationStats:
    def test_stats(self, fm):
        fm.register_agent("a1")
        fm.register_agent("a2")
        s = fm.create_session(initiator="a1")
        fm.record_handoff(s.trace_id, "a1", "a2")
        fm.complete_session(s.trace_id)

        stats = fm.stats()
        assert stats["registered_agents"] == 2
        assert stats["active_sessions"] == 0
        assert stats["completed_sessions"] == 1
        assert stats["total_handoffs"] == 1


# ── API Endpoints ────────────────────────────────────────────────────


class TestFederationAPI:
    def test_register_agent_api(self, client):
        token = get_admin_token(client)
        resp = client.post(
            "/federation/agents",
            json={"agent_id": "api-agent", "cluster": "test"},
            headers=auth(token),
        )
        assert resp.status_code == 200
        assert resp.json()["agent_id"] == "api-agent"

    def test_list_agents_api(self, client):
        token = get_admin_token(client)
        client.post("/federation/agents", json={"agent_id": "a1"}, headers=auth(token))
        client.post("/federation/agents", json={"agent_id": "a2"}, headers=auth(token))

        resp = client.get("/federation/agents", headers=auth(token))
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_create_session_api(self, client):
        token = get_admin_token(client)
        resp = client.post(
            "/federation/sessions",
            json={"initiator": "agent-1"},
            headers=auth(token),
        )
        assert resp.status_code == 200
        assert resp.json()["initiator"] == "agent-1"

    def test_handoff_and_graph_api(self, client):
        token = get_admin_token(client)

        # Create session
        session = client.post(
            "/federation/sessions",
            json={"initiator": "a1"},
            headers=auth(token),
        ).json()
        trace_id = session["trace_id"]

        # Record handoff
        resp = client.post(
            f"/federation/sessions/{trace_id}/handoff",
            json={"from_agent": "a1", "to_agent": "a2", "tool_name": "query"},
            headers=auth(token),
        )
        assert resp.status_code == 200

        # Get graph
        graph = client.get(
            f"/federation/sessions/{trace_id}/graph",
            headers=auth(token),
        ).json()
        assert graph["handoff_count"] == 1

    def test_stats_api(self, client):
        token = get_admin_token(client)
        resp = client.get("/federation/stats", headers=auth(token))
        assert resp.status_code == 200
        assert "registered_agents" in resp.json()

    def test_add_rule_api(self, client):
        token = get_admin_token(client)
        resp = client.post(
            "/federation/rules",
            json={
                "id": "r1",
                "from_agent": "*",
                "to_agent": "secure",
                "action": "BLOCK",
            },
            headers=auth(token),
        )
        assert resp.status_code == 200

        rules = client.get("/federation/rules", headers=auth(token)).json()
        assert len(rules) == 1
