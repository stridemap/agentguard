"""Tests for the storage abstraction and store factory.

Covers:
- SQLite store created from sqlite:/// URL
- SQLite store created from plain path
- Default URL when env var not set
- PostgreSQL URL detection (import only, no live PG needed)
- In-memory queue created by default
- Redis queue detection (import only, no live Redis needed)
- Storage abstraction: SQLite append/get/verify via factory
"""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from agentguard.event_store import EventQueue, EventStore
from agentguard.models import AgentEvent
from agentguard.store_factory import create_queue, create_store


def make_event(tool_name: str = "tool") -> AgentEvent:
    event = AgentEvent(
        agent_id="factory-test",
        session_id="factory-session",
        tool_name=tool_name,
        run_id=uuid4(),
        input_str="input",
        input_hash=AgentEvent.compute_hash("input"),
    )
    event.finalize(output="output", latency_ms=1.0)
    event.policy_result = "ALLOW"
    return event


# ── Factory: store creation ──────────────────────────────────────────


class TestCreateStore:
    def test_sqlite_from_url(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        store = create_store(f"sqlite:///{db_path}")
        assert isinstance(store, EventStore)
        store.append(make_event())
        assert store.get_event_count() == 1
        store.close()

    def test_sqlite_from_plain_path(self, tmp_path):
        db_path = str(tmp_path / "plain.db")
        store = create_store(db_path)
        assert isinstance(store, EventStore)
        store.append(make_event())
        assert store.get_event_count() == 1
        store.close()

    def test_default_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        store = create_store()
        assert isinstance(store, EventStore)
        store.close()

    def test_postgresql_url_detected(self):
        """PostgreSQL URL is recognized — actual connection not tested."""
        # Will fail with ImportError (psycopg2) or connection error
        with pytest.raises((ImportError, OSError)):
            create_store("postgresql://user:pass@localhost:5432/test")

    def test_sqlite_memory(self):
        store = create_store("sqlite:///:memory:")
        assert isinstance(store, EventStore)
        store.append(make_event())
        assert store.get_event_count() == 1
        store.close()


# ── Factory: queue creation ──────────────────────────────────────────


class TestCreateQueue:
    def test_memory_queue_default(self, tmp_path):
        store = EventStore(db_path=str(tmp_path / "q.db"))
        queue = create_queue(store)
        assert isinstance(queue, EventQueue)
        store.close()

    def test_memory_queue_explicit(self, tmp_path):
        store = EventStore(db_path=str(tmp_path / "q.db"))
        queue = create_queue(store, backend="memory")
        assert isinstance(queue, EventQueue)
        store.close()

    def test_redis_backend_detected(self, tmp_path):
        """Redis backend is recognized — queue object created."""
        from agentguard.redis_queue import RedisEventQueue

        store = EventStore(db_path=str(tmp_path / "q.db"))
        queue = create_queue(
            store, backend="redis", redis_url="redis://localhost:6379/0"
        )
        assert isinstance(queue, RedisEventQueue)
        store.close()


# ── End-to-end: factory → store → queue → verify ────────────────────


class TestFactoryEndToEnd:
    def test_sqlite_full_pipeline(self, tmp_path):
        db_path = str(tmp_path / "e2e.db")
        store = create_store(f"sqlite:///{db_path}")
        queue = create_queue(store, backend="memory")
        queue.start()

        for i in range(20):
            queue.enqueue(make_event(f"tool_{i}"))

        time.sleep(0.5)

        assert store.get_event_count() == 20
        assert queue.events_written == 20
        assert queue.events_dropped == 0

        # Verify audit chain
        result = store.verify_chain()
        assert result["is_valid"] is True
        assert result["total_events"] == 20

        queue.stop()
        store.close()

    def test_env_var_override(self, tmp_path, monkeypatch):
        db_path = str(tmp_path / "env.db")
        monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
        store = create_store()
        store.append(make_event())
        assert store.get_event_count() == 1
        store.close()
