"""Tests for the SHA-256 cryptographic audit chain.

Covers:
- verify_chain() on valid chain → True
- Tamper detection: modify any field → chain breaks at that event
- Genesis event has prev_hash of all zeros
- 100 events → valid chain
- CLI verify-chain command output
"""

from __future__ import annotations

import sqlite3
from uuid import uuid4

import pytest

from agentguard.event_store import EventStore
from agentguard.models import AgentEvent

# ── Helpers ──────────────────────────────────────────────────────────


def make_event(tool_name: str = "tool") -> AgentEvent:
    event = AgentEvent(
        agent_id="audit-agent",
        session_id="audit-session",
        tool_name=tool_name,
        run_id=uuid4(),
        input_str="input data",
        input_hash=AgentEvent.compute_hash("input data"),
    )
    event.finalize(output="output data", latency_ms=5.0)
    event.policy_result = "ALLOW"
    return event


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def store(tmp_path):
    db_path = str(tmp_path / "chain.db")
    s = EventStore(db_path=db_path)
    yield s
    s.close()


# ── Valid chain tests ────────────────────────────────────────────────


class TestValidChain:
    def test_empty_chain_is_valid(self, store):
        result = store.verify_chain()
        assert result["is_valid"] is True
        assert result["total_events"] == 0

    def test_single_event_chain_valid(self, store):
        store.append(make_event())
        result = store.verify_chain()
        assert result["is_valid"] is True
        assert result["total_events"] == 1

    def test_100_events_chain_valid(self, store):
        for i in range(100):
            store.append(make_event(f"tool_{i}"))
        result = store.verify_chain()
        assert result["is_valid"] is True
        assert result["total_events"] == 100

    def test_genesis_event_has_zero_prev_hash(self, store):
        store.append(make_event())
        conn = store._get_conn()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM events ORDER BY rowid LIMIT 1").fetchone()
        assert row["prev_hash"] == "0" * 64

    def test_event_hash_is_64_hex_chars(self, store):
        store.append(make_event())
        conn = store._get_conn()
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT event_hash FROM events LIMIT 1").fetchone()
        assert len(row["event_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in row["event_hash"])

    def test_chain_links_prev_to_current(self, store):
        """Second event's prev_hash = first event's event_hash."""
        store.append(make_event("first"))
        store.append(make_event("second"))

        conn = store._get_conn()
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events ORDER BY rowid").fetchall()

        assert rows[1]["prev_hash"] == rows[0]["event_hash"]

    def test_verification_latency_returned(self, store):
        for _ in range(10):
            store.append(make_event())
        result = store.verify_chain()
        assert result["verification_latency_ms"] > 0


# ── Tamper detection tests ───────────────────────────────────────────


class TestTamperDetection:
    def test_modify_tool_name_breaks_chain(self, store):
        """Modify tool_name of event #1 → chain breaks at event #1."""
        store.append(make_event("original"))
        store.append(make_event("second"))

        # Tamper: change tool_name
        conn = store._get_conn()
        conn.execute("UPDATE events SET tool_name = 'HACKED' WHERE rowid = 1")
        conn.commit()

        result = store.verify_chain()
        assert result["is_valid"] is False
        assert result["first_tampered_event_id"] is not None

    def test_modify_event_hash_breaks_chain(self, store):
        """Modify event_hash directly → chain breaks."""
        store.append(make_event())
        store.append(make_event())

        conn = store._get_conn()
        conn.execute(
            "UPDATE events SET event_hash = 'deadbeef' || event_hash WHERE rowid = 1"
        )
        conn.commit()

        result = store.verify_chain()
        assert result["is_valid"] is False

    def test_modify_timestamp_breaks_chain(self, store):
        store.append(make_event())
        store.append(make_event())

        conn = store._get_conn()
        conn.execute(
            "UPDATE events SET timestamp = '2020-01-01T00:00:00' WHERE rowid = 1"
        )
        conn.commit()

        result = store.verify_chain()
        assert result["is_valid"] is False

    def test_modify_middle_event_breaks_at_that_point(self, store):
        """Modify event #50 out of 100 → chain breaks at event #50."""
        for i in range(100):
            store.append(make_event(f"tool_{i}"))

        conn = store._get_conn()
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT event_id FROM events ORDER BY rowid").fetchall()
        target_id = rows[49]["event_id"]  # Event #50 (0-indexed #49)

        conn.execute(
            "UPDATE events SET agent_id = 'TAMPERED' WHERE event_id = ?",
            (target_id,),
        )
        conn.commit()

        result = store.verify_chain()
        assert result["is_valid"] is False
        assert result["first_tampered_event_id"] == target_id

    def test_delete_middle_event_breaks_chain(self, store):
        """Delete an event from the middle → chain breaks."""
        for _ in range(5):
            store.append(make_event())

        conn = store._get_conn()
        conn.execute("DELETE FROM events WHERE rowid = 3")
        conn.commit()

        result = store.verify_chain()
        assert result["is_valid"] is False

    def test_modify_risk_flags_breaks_chain(self, store):
        store.append(make_event())

        conn = store._get_conn()
        conn.execute(
            "UPDATE events SET risk_flags = '[\"pii_detected\"]' WHERE rowid = 1"
        )
        conn.commit()

        result = store.verify_chain()
        assert result["is_valid"] is False


# ── CLI verify-chain test ────────────────────────────────────────────


class TestVerifyChainCLI:
    def test_cli_valid_chain(self, tmp_path):
        """python -m agentguard verify-chain exits 0 on valid chain."""
        import subprocess

        db_path = str(tmp_path / "cli.db")
        store = EventStore(db_path=db_path)
        for _ in range(5):
            store.append(make_event())
        store.close()

        result = subprocess.run(
            ["python3", "-m", "agentguard", "verify-chain", "--db", db_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "valid" in result.stdout.lower()

    def test_cli_tampered_chain(self, tmp_path):
        """python -m agentguard verify-chain exits 1 on tampered chain."""
        import subprocess

        db_path = str(tmp_path / "tampered.db")
        store = EventStore(db_path=db_path)
        for _ in range(5):
            store.append(make_event())

        # Tamper
        conn = store._get_conn()
        conn.execute("UPDATE events SET tool_name = 'EVIL' WHERE rowid = 1")
        conn.commit()
        store.close()

        result = subprocess.run(
            ["python3", "-m", "agentguard", "verify-chain", "--db", db_path],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "broken" in result.stdout.lower() or "tamper" in result.stdout.lower()
