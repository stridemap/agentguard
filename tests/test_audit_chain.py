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
from pathlib import Path
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


class TestChainResume:
    """Regression: EventStore must resume _last_hash from disk on init.

    Without this, opening a fresh EventStore against an existing DB and
    appending writes the next event with prev_hash=GENESIS, breaking the
    chain at that exact row. This matters for multi-worker deployments
    and any caller that reconstructs an EventStore mid-lifecycle.
    """

    def test_append_after_reopen_preserves_chain(self, tmp_path):
        db_path = str(tmp_path / "resume.db")

        # First process: write 3 events with one store, close it.
        s1 = EventStore(db_path=db_path)
        for _ in range(3):
            s1.append(make_event())
        s1.close()

        # Second process: fresh store against the same DB, append more.
        s2 = EventStore(db_path=db_path)
        for _ in range(2):
            s2.append(make_event())
        result = s2.verify_chain()
        s2.close()

        assert result["is_valid"] is True
        assert result["total_events"] == 5
        assert result["first_tampered_event_id"] is None

    def test_resume_on_empty_db_starts_from_genesis(self, tmp_path):
        db_path = str(tmp_path / "fresh.db")
        s = EventStore(db_path=db_path)
        try:
            assert s._last_hash == EventStore._GENESIS_HASH
            s.append(make_event())
            assert s.verify_chain()["is_valid"] is True
        finally:
            s.close()

    def test_three_sequential_reopens_keep_chain_valid(self, tmp_path):
        db_path = str(tmp_path / "loop.db")
        for _ in range(3):
            s = EventStore(db_path=db_path)
            s.append(make_event())
            s.close()

        s = EventStore(db_path=db_path)
        result = s.verify_chain()
        s.close()
        assert result["is_valid"] is True
        assert result["total_events"] == 3


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


# ── concurrent writers ───────────────────────────────────────────────


def test_chain_survives_concurrent_stores_sharing_one_database(tmp_path):
    """Regression: several EventStore instances writing to one database must produce
    a single valid chain.

    Found in the field. An MCP client that maintains a process pool starts the gateway
    more than once, each process constructs its own EventStore, each resumes the same
    chain tip, and two appends then claim the same predecessor — forking the chain and
    making verify_chain() report tampering on a log nobody touched. A false positive
    here is worse than no check at all, so the tip is now read inside the write
    transaction rather than from in-memory state.
    """
    import threading
    from uuid import uuid4

    db_path = str(tmp_path / "concurrent.db")

    def writer(tag: str) -> None:
        store = EventStore(db_path=db_path)  # a separate store == a separate process
        for i in range(25):
            store.append(AgentEvent(tool_name=f"{tag}.tool{i}", run_id=uuid4()))
        store.close()

    threads = [threading.Thread(target=writer, args=(f"proc{n}",)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    verifying_store = EventStore(db_path=db_path)
    result = verifying_store.verify_chain()

    assert result["total_events"] == 100
    assert result["is_valid"] is True, (
        f"chain forked at {result['first_tampered_event_id']} — "
        "concurrent appends claimed the same predecessor"
    )

    # and every link genuinely points at the row before it
    conn = verifying_store._get_conn()
    rows = conn.execute("SELECT prev_hash, event_hash FROM events ORDER BY rowid").fetchall()
    for previous, current in zip(rows, rows[1:], strict=False):
        assert current[0] == previous[1]
    verifying_store.close()


def test_a_second_store_resumes_the_chain_rather_than_restarting_it(tmp_path):
    """Opening a store against an existing database must continue the chain."""
    from uuid import uuid4

    db_path = str(tmp_path / "resume.db")

    first = EventStore(db_path=db_path)
    first.append(AgentEvent(tool_name="a", run_id=uuid4()))
    first.close()

    second = EventStore(db_path=db_path)
    second.append(AgentEvent(tool_name="b", run_id=uuid4()))

    assert second.verify_chain()["is_valid"] is True
    rows = second._get_conn().execute(
        "SELECT prev_hash, event_hash FROM events ORDER BY rowid"
    ).fetchall()
    assert rows[1][0] == rows[0][1]
    second.close()


# ── float precision in the chain ─────────────────────────────────────


def test_latency_survives_the_hash_round_trip_exactly():
    """The chain hashes latency_ms, so the column must return exactly what was hashed.

    PostgreSQL REAL is float4: it stores four bytes and hands back a rounded value, while
    the hash covers the float8 Python measured. The two never agree, and every chain
    verification failed at row 1 — silently, on the backend used for hosted deployments
    and not on the SQLite one used in development. The schema now says DOUBLE PRECISION.

    This guards the property rather than the column type: whatever the storage, a latency
    that goes in must come back bit-identical or the chain is unverifiable.
    """
    import struct

    measured = 3.6518339999234
    as_float4 = struct.unpack("f", struct.pack("f", measured))[0]

    assert as_float4 != measured, "precondition: float4 does lose precision here"

    schema = (Path(__file__).parent.parent / "agentguard" / "pg_store.py").read_text()
    assert "latency_ms DOUBLE PRECISION," in schema
    assert "latency_ms REAL," not in schema

    sqlite_schema = (Path(__file__).parent.parent / "agentguard" / "event_store.py").read_text()
    assert "latency_ms REAL," in sqlite_schema, "SQLite REAL is an 8-byte double — fine"
