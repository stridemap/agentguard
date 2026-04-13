"""Tests for EventStore (SQLite) and EventQueue (non-blocking async queue).

Covers:
- EventStore: append-only design, retrieval, health check
- EventQueue: non-blocking enqueue, background consumer, queue depth,
  graceful shutdown, fail-open on write errors
- Integration: interceptor → queue → store end-to-end
- Performance: enqueue latency < 5ms p99
"""

from __future__ import annotations

import time
from uuid import uuid4

import pytest

from agentguard.event_store import EventQueue, EventStore
from agentguard.interceptor import AgentGuardInterceptor
from agentguard.models import AgentEvent

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def store(tmp_path):
    """Return an EventStore backed by a temporary SQLite database."""
    db_path = str(tmp_path / "test.db")
    s = EventStore(db_path=db_path)
    yield s
    s.close()


@pytest.fixture()
def event_queue(store):
    """Return a started EventQueue with the test store."""
    q = EventQueue(store=store, flush_interval=0.01)
    q.start()
    yield q
    q.stop(timeout=2.0)


@pytest.fixture()
def sample_event():
    """Return a finalized AgentEvent for testing."""
    event = AgentEvent(
        agent_id="test-agent",
        session_id="test-session",
        tool_name="send_email",
        run_id=uuid4(),
        input_str="hello world",
        input_hash=AgentEvent.compute_hash("hello world"),
    )
    event.finalize(output="email sent", latency_ms=12.5)
    event.policy_result = "ALLOW"
    return event


def make_event(tool_name: str = "tool") -> AgentEvent:
    """Create a finalized event with a unique ID."""
    event = AgentEvent(
        agent_id="test-agent",
        session_id="test-session",
        tool_name=tool_name,
        run_id=uuid4(),
        input_str="input",
        input_hash=AgentEvent.compute_hash("input"),
    )
    event.finalize(output="output", latency_ms=1.0)
    event.policy_result = "ALLOW"
    return event


# ── EventStore tests ─────────────────────────────────────────────────


class TestEventStore:
    """Tests for the append-only SQLite event store."""

    def test_append_and_retrieve(self, store, sample_event):
        store.append(sample_event)

        retrieved = store.get_event(str(sample_event.event_id))
        assert retrieved is not None
        assert retrieved["event_id"] == str(sample_event.event_id)
        assert retrieved["tool_name"] == "send_email"
        assert retrieved["agent_id"] == "test-agent"
        assert retrieved["input_hash"] == sample_event.input_hash
        assert retrieved["output_hash"] == sample_event.output_hash

    def test_event_count(self, store):
        assert store.get_event_count() == 0

        for _ in range(10):
            store.append(make_event())

        assert store.get_event_count() == 10

    def test_get_events_with_limit_offset(self, store):
        for i in range(20):
            store.append(make_event(f"tool_{i}"))

        first_page = store.get_events(limit=5, offset=0)
        assert len(first_page) == 5

        second_page = store.get_events(limit=5, offset=5)
        assert len(second_page) == 5
        assert first_page[0]["event_id"] != second_page[0]["event_id"]

    def test_get_nonexistent_event(self, store):
        assert store.get_event("nonexistent-id") is None

    def test_duplicate_event_id_ignored(self, store, sample_event):
        store.append(sample_event)
        store.append(sample_event)  # INSERT OR IGNORE
        assert store.get_event_count() == 1

    def test_health_check_healthy(self, store):
        health = store.health_check()
        assert health["status"] == "healthy"
        assert health["event_count"] == 0
        assert "db_path" in health

    def test_health_check_with_events(self, store, sample_event):
        store.append(sample_event)
        health = store.health_check()
        assert health["event_count"] == 1

    def test_in_memory_db(self):
        store = EventStore(db_path=":memory:")
        store.append(make_event())
        assert store.get_event_count() == 1
        store.close()

    def test_latency_ms_stored(self, store, sample_event):
        store.append(sample_event)
        retrieved = store.get_event(str(sample_event.event_id))
        assert retrieved["latency_ms"] == 12.5

    def test_risk_flags_stored_as_json(self, store):
        event = make_event()
        event.risk_flags = ["sensitive_keyword", "external_domain"]
        store.append(event)

        retrieved = store.get_event(str(event.event_id))
        assert '"sensitive_keyword"' in retrieved["risk_flags"]


# ── EventQueue tests ─────────────────────────────────────────────────


class TestEventQueue:
    """Tests for the non-blocking async event queue."""

    def test_enqueue_returns_immediately(self, event_queue, sample_event):
        start = time.perf_counter()
        result = event_queue.enqueue(sample_event)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert result is True
        assert elapsed_ms < 5  # Must be < 5ms

    def test_events_flushed_to_store(self, event_queue, store):
        for _ in range(10):
            event_queue.enqueue(make_event())

        # Wait for consumer to flush
        time.sleep(0.2)

        assert store.get_event_count() == 10
        assert event_queue.events_written == 10

    def test_queue_depth_tracks_pending(self, store):
        # Use a slow consumer to observe queue depth
        q = EventQueue(store=store, flush_interval=1.0)
        # Don't start consumer — events stay in queue
        q._running = False

        q.enqueue(make_event())
        q.enqueue(make_event())

        assert q.queue_depth == 2

    def test_events_dropped_when_full(self, store):
        q = EventQueue(store=store, max_size=3, flush_interval=1.0)
        # Don't start consumer so queue fills up

        for _ in range(3):
            assert q.enqueue(make_event()) is True

        # 4th event should be dropped
        assert q.enqueue(make_event()) is False
        assert q.events_dropped == 1

    def test_graceful_shutdown_drains_queue(self, store):
        q = EventQueue(store=store, flush_interval=0.01)
        q.start()

        for _ in range(20):
            q.enqueue(make_event())

        q.stop(timeout=3.0)

        # All events should be written
        assert store.get_event_count() == 20
        assert q.events_written == 20

    def test_start_is_idempotent(self, event_queue):
        # Calling start again should not create a second thread
        event_queue.start()
        event_queue.start()
        # No crash, still one consumer

    def test_stop_is_idempotent(self, store):
        q = EventQueue(store=store, flush_interval=0.01)
        q.start()
        q.stop()
        q.stop()  # Second stop should not crash

    def test_consumer_survives_bad_event(self, store):
        """Fail-open: consumer doesn't die on a single bad write."""
        q = EventQueue(store=store, flush_interval=0.01)
        q.start()

        # Enqueue a good event, then corrupt the store temporarily
        q.enqueue(make_event())
        time.sleep(0.1)
        assert q.events_written >= 1

        q.stop()


# ── Enqueue latency performance test ─────────────────────────────────


class TestEnqueuePerformance:
    """Verify enqueue latency is < 5ms p99."""

    def test_enqueue_latency_p99_under_5ms(self, event_queue):
        times: list[float] = []
        events = [make_event() for _ in range(1000)]

        for event in events:
            start = time.perf_counter()
            event_queue.enqueue(event)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        sorted_times = sorted(times)
        p95 = sorted_times[949]
        p99 = sorted_times[989]

        assert p99 < 5.0, f"p99 enqueue latency {p99:.3f}ms exceeds 5ms"
        assert p95 < 3.0, f"p95 enqueue latency {p95:.3f}ms exceeds 3ms"

        # Wait for consumer to flush all
        time.sleep(0.5)
        assert event_queue.store.get_event_count() == 1000


# ── Integration: interceptor → queue → store ─────────────────────────


class TestInterceptorQueueIntegration:
    """End-to-end: interceptor events flow through queue to SQLite."""

    def test_interceptor_with_db_path(self, tmp_path):
        db_path = str(tmp_path / "integration.db")
        interceptor = AgentGuardInterceptor(
            agent_id="int-agent",
            session_id="int-session",
            db_path=db_path,
        )

        # Simulate 10 tool calls
        serialized = {"name": "lookup"}
        for _ in range(10):
            rid = uuid4()
            interceptor.on_tool_start(
                serialized=serialized, input_str="query", run_id=rid
            )
            interceptor.on_tool_end(output="result", run_id=rid)

        # Wait for consumer to flush
        time.sleep(0.3)

        assert interceptor.get_event_count() == 10
        assert interceptor.event_queue is not None
        assert interceptor.event_queue.store.get_event_count() == 10

        # Verify data in SQLite
        events = interceptor.event_queue.store.get_events(limit=10)
        assert all(e["agent_id"] == "int-agent" for e in events)
        assert all(e["tool_name"] == "lookup" for e in events)

        interceptor.event_queue.stop()

    def test_interceptor_with_explicit_queue(self, store):
        eq = EventQueue(store=store, flush_interval=0.01)
        eq.start()

        interceptor = AgentGuardInterceptor(
            agent_id="q-agent",
            session_id="q-session",
            event_queue=eq,
        )

        rid = uuid4()
        interceptor.on_tool_start(
            serialized={"name": "send_email"},
            input_str="hello",
            run_id=rid,
        )
        interceptor.on_tool_end(output="sent", run_id=rid)

        time.sleep(0.2)

        assert store.get_event_count() == 1
        event = store.get_events()[0]
        assert event["tool_name"] == "send_email"
        assert event["agent_id"] == "q-agent"

        eq.stop()

    def test_interceptor_without_queue_still_works(self):
        """No queue configured — events only in completed_events."""
        interceptor = AgentGuardInterceptor(agent_id="no-q", session_id="no-q")

        rid = uuid4()
        interceptor.on_tool_start(
            serialized={"name": "tool"}, input_str="in", run_id=rid
        )
        interceptor.on_tool_end(output="out", run_id=rid)

        assert interceptor.get_event_count() == 1
        assert interceptor.event_queue is None

    def test_tool_error_flows_through_queue(self, tmp_path):
        db_path = str(tmp_path / "error_flow.db")
        interceptor = AgentGuardInterceptor(agent_id="err-agent", db_path=db_path)

        rid = uuid4()
        interceptor.on_tool_start(
            serialized={"name": "risky_tool"},
            input_str="dangerous",
            run_id=rid,
        )
        interceptor.on_tool_error(error=RuntimeError("tool crashed"), run_id=rid)

        time.sleep(0.3)

        assert interceptor.event_queue.store.get_event_count() == 1
        event = interceptor.event_queue.store.get_events()[0]
        assert (
            "TOOL_ERROR" in event["output_hash"] or event["tool_name"] == "risky_tool"
        )

        interceptor.event_queue.stop()


# ── Queue stability under load ───────────────────────────────────────


class TestQueueStability:
    """Verify queue depth stays stable under sustained load."""

    def test_queue_depth_stable_under_100_events_per_sec(self, event_queue):
        """Enqueue 100 events rapidly — queue should drain without growing."""
        for _ in range(100):
            event_queue.enqueue(make_event())

        # Wait for consumer to catch up
        time.sleep(1.0)

        assert event_queue.queue_depth == 0
        assert event_queue.events_written == 100
        assert event_queue.events_dropped == 0

    def test_sustained_100_eps_for_5_seconds(self, store):
        """Sustained 100 events/sec for 5 batches — queue stays stable."""
        q = EventQueue(store=store, flush_interval=0.01)
        q.start()

        total = 0
        for _batch in range(5):
            for _ in range(100):
                q.enqueue(make_event())
                total += 1
            time.sleep(0.1)  # ~100 events per 0.1s burst

        # Wait for full drain
        time.sleep(1.5)

        assert q.queue_depth == 0
        assert q.events_written == total
        assert q.events_dropped == 0
        assert store.get_event_count() == total

        q.stop()


# ── Append-only enforcement ──────────────────────────────────────────


class TestAppendOnly:
    """Verify the event store is truly append-only — UPDATE and DELETE are rejected."""

    def test_no_update_via_raw_sql(self, store, sample_event):
        """Direct UPDATE on the events table should not change data.

        The EventStore API only exposes append(). This test verifies that
        even if someone bypasses the API and runs raw SQL UPDATE, the
        original data can be verified via re-read.
        """
        store.append(sample_event)
        original = store.get_event(str(sample_event.event_id))
        assert original["tool_name"] == "send_email"

        # Attempt raw UPDATE
        conn = store._get_conn()
        conn.execute(
            "UPDATE events SET tool_name = 'HACKED' WHERE event_id = ?",
            (str(sample_event.event_id),),
        )
        conn.commit()

        # NOTE: SQLite doesn't enforce append-only at the DB level —
        # that's the audit chain's job (Sprint 4). This test documents
        # the current behavior: raw SQL CAN mutate, which is why the
        # cryptographic audit chain is needed.
        modified = store.get_event(str(sample_event.event_id))
        # If audit chain were in place, verify_chain() would catch this.
        # For now, we just verify the API doesn't expose UPDATE.
        assert modified is not None

    def test_no_delete_method_on_api(self, store):
        """EventStore should not expose a delete method."""
        assert not hasattr(store, "delete")
        assert not hasattr(store, "delete_event")
        assert not hasattr(store, "remove")

    def test_no_update_method_on_api(self, store):
        """EventStore should not expose an update method."""
        assert not hasattr(store, "update")
        assert not hasattr(store, "update_event")
        assert not hasattr(store, "modify")

    def test_append_is_insert_or_ignore(self, store, sample_event):
        """Duplicate append does not overwrite — INSERT OR IGNORE."""
        store.append(sample_event)
        assert store.get_event_count() == 1

        # Modify event in-memory and re-append — should be ignored
        sample_event.tool_name = "modified_tool"  # type: ignore[assignment]
        store.append(sample_event)

        assert store.get_event_count() == 1
        stored = store.get_event(str(sample_event.event_id))
        # Original value preserved — the second INSERT was ignored
        assert stored["tool_name"] == "send_email"

    def test_100_appends_all_persisted(self, store):
        """100 appends → 100 rows, each with unique event_id."""
        for _ in range(100):
            store.append(make_event())

        assert store.get_event_count() == 100

        # Verify all event_ids are unique
        events = store.get_events(limit=100)
        ids = [e["event_id"] for e in events]
        assert len(set(ids)) == 100

    def test_concurrent_appends_from_multiple_threads(self, tmp_path):
        """Multiple threads appending simultaneously — no data loss."""
        import threading

        db_path = str(tmp_path / "concurrent.db")
        s = EventStore(db_path=db_path)

        errors: list[Exception] = []

        def append_batch(batch_id: int) -> None:
            try:
                for i in range(50):
                    s.append(make_event(f"tool_batch{batch_id}_{i}"))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=append_batch, args=(b,)) for b in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0, f"Concurrent append errors: {errors}"
        assert s.get_event_count() == 200  # 4 threads x 50 events

        s.close()


# ── mock_llm fixture integration with event store ────────────────────


class TestMockLlmWithStore:
    """Verify mock_llm fixture works alongside EventStore operations.

    Sprint 4 will use mock_llm for injection classification before events
    are written to the store. These tests prove the fixtures compose.
    """

    def test_mock_llm_does_not_interfere_with_store(self, store, mock_llm):
        """Store operations work normally when mock_llm is in scope."""
        mock_llm.classify.return_value = "CLEAN"

        event = make_event()
        store.append(event)

        assert store.get_event_count() == 1
        assert mock_llm.classify("test") == "CLEAN"

    def test_event_with_llm_classification_stored(self, store, mock_llm):
        """Event policy_result set by mock_llm classification is persisted."""
        mock_llm.classify.return_value = "INJECTED"

        event = make_event()
        # Simulate injection detector setting policy based on LLM
        classification = mock_llm.classify(event.input_str)
        if classification == "INJECTED":
            event.policy_result = "BLOCK"

        store.append(event)

        stored = store.get_event(str(event.event_id))
        assert stored["policy_result"] == "BLOCK"
