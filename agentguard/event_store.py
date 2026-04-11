"""Append-only event store with non-blocking async write queue.

Architecture:
    Interceptor → EventQueue (in-memory, thread-safe) → Consumer Thread → SQLite

The interceptor enqueues events and returns immediately (<5ms p99).
A background daemon thread consumes the queue and flushes to SQLite.
The event store is append-only — no UPDATE or DELETE operations.

Usage:
    from agentguard.event_store import EventQueue, EventStore

    store = EventStore(db_path="agentguard.db")
    queue = EventQueue(store=store)
    queue.start()

    # From interceptor (non-blocking):
    queue.enqueue(event)

    # Graceful shutdown:
    queue.stop()
"""

from __future__ import annotations

import contextlib
import json
import queue
import sqlite3
import threading
from typing import Any

from agentguard.logging import logger
from agentguard.models import AgentEvent

# ── SQLite Event Store ───────────────────────────────────────────────


_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    run_id TEXT NOT NULL,
    parent_run_id TEXT,
    input_hash TEXT NOT NULL,
    output_hash TEXT NOT NULL,
    latency_ms REAL,
    risk_flags TEXT NOT NULL,
    policy_result TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL DEFAULT ''
)
"""

_INSERT_EVENT_SQL = """
INSERT OR IGNORE INTO events (
    event_id, timestamp, agent_id, session_id, tool_name,
    run_id, parent_run_id, input_hash, output_hash,
    latency_ms, risk_flags, policy_result
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class EventStore:
    """Append-only SQLite event store.

    All writes go through append(). No UPDATE or DELETE operations are
    exposed. The database schema is auto-created on initialization.

    Attributes:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: str = "agentguard.db") -> None:
        """Initialize the event store and create the schema.

        Args:
            db_path: Path to the SQLite database file. Use ":memory:" for tests.
        """
        self.db_path = db_path
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self.db_path)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self) -> None:
        """Create the events table if it doesn't exist."""
        conn = self._get_conn()
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()

    def append(self, event: AgentEvent) -> None:
        """Append a single event to the store.

        This is the only write operation. No UPDATE or DELETE is allowed.

        Args:
            event: A finalized AgentEvent to persist.
        """
        conn = self._get_conn()
        conn.execute(
            _INSERT_EVENT_SQL,
            (
                str(event.event_id),
                event.timestamp.isoformat(),
                event.agent_id,
                event.session_id,
                event.tool_name,
                str(event.run_id),
                str(event.parent_run_id) if event.parent_run_id else None,
                event.input_hash,
                event.output_hash,
                event.latency_ms,
                json.dumps(event.risk_flags),
                event.policy_result,
            ),
        )
        conn.commit()

    def get_event_count(self) -> int:
        """Return the total number of events in the store."""
        conn = self._get_conn()
        row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
        return row[0] if row else 0

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        """Retrieve a single event by its ID.

        Args:
            event_id: The UUID string of the event.

        Returns:
            A dict of event fields, or None if not found.
        """
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            return None
        return dict(row)

    def get_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        """Retrieve events in insertion order.

        Args:
            limit: Maximum number of events to return.
            offset: Number of events to skip.

        Returns:
            List of event dicts.
        """
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp ASC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [dict(r) for r in rows]

    def health_check(self) -> dict[str, Any]:
        """Return health status of the event store.

        Returns:
            Dict with db_path, event_count, and status.
        """
        try:
            count = self.get_event_count()
            return {
                "status": "healthy",
                "db_path": self.db_path,
                "event_count": count,
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "db_path": self.db_path,
                "error": str(e),
            }

    def close(self) -> None:
        """Close the thread-local database connection."""
        if hasattr(self._local, "conn") and self._local.conn is not None:
            self._local.conn.close()
            self._local.conn = None


# ── Non-Blocking Event Queue ─────────────────────────────────────────


class EventQueue:
    """Thread-safe non-blocking queue between the interceptor and event store.

    The interceptor calls enqueue() which puts the event onto an in-memory
    queue and returns immediately. A background daemon thread continuously
    drains the queue and writes events to the EventStore.

    This decouples tool-call latency from database I/O — the interceptor
    never waits for a DB write.

    Attributes:
        store: The EventStore backend to flush events to.
        queue: Thread-safe FIFO queue.
        max_size: Maximum queue depth (0 = unlimited).
    """

    def __init__(
        self,
        store: EventStore,
        max_size: int = 10_000,
        flush_interval: float = 0.1,
    ) -> None:
        """Initialize the event queue.

        Args:
            store: EventStore backend for persistence.
            max_size: Maximum queue depth. Events are dropped with a
                WARNING if the queue is full. 0 = unlimited.
            flush_interval: Seconds the consumer sleeps when the queue
                is empty. Lower = more responsive, higher = less CPU.
        """
        self.store = store
        self.max_size = max_size
        self.flush_interval = flush_interval
        self._queue: queue.Queue[AgentEvent | None] = queue.Queue(maxsize=max_size)
        self._consumer_thread: threading.Thread | None = None
        self._running = False
        self._events_written = 0
        self._events_dropped = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        """Start the background consumer thread.

        The consumer is a daemon thread — it dies automatically when the
        main process exits, but stop() should be called for graceful shutdown.
        """
        if self._running:
            return

        self._running = True
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop,
            name="agentguard-event-consumer",
            daemon=True,
        )
        self._consumer_thread.start()
        logger.bind(module="agentguard.event_queue").info(
            "Event queue consumer started (max_size={max_size})",
            max_size=self.max_size,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the consumer thread gracefully.

        Sends a sentinel None to the queue and waits for the consumer to
        drain remaining events before exiting.

        Args:
            timeout: Maximum seconds to wait for the consumer to finish.
        """
        if not self._running:
            return

        self._running = False
        # Send sentinel to unblock the consumer
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(None)

        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=timeout)
            self._consumer_thread = None

        logger.bind(module="agentguard.event_queue").info(
            "Event queue consumer stopped (written={written}, dropped={dropped})",
            written=self._events_written,
            dropped=self._events_dropped,
        )

    def enqueue(self, event: AgentEvent) -> bool:
        """Enqueue an event for asynchronous persistence.

        This method is non-blocking. If the queue is full, the event is
        dropped with a WARNING log. Returns immediately — never waits
        for database I/O.

        Args:
            event: A finalized AgentEvent to persist.

        Returns:
            True if the event was enqueued, False if dropped.
        """
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            with self._lock:
                self._events_dropped += 1
            logger.warning(
                "Event queue full — dropping event {event_id} (dropped={dropped})",
                event_id=str(event.event_id),
                dropped=self._events_dropped,
            )
            return False

    @property
    def queue_depth(self) -> int:
        """Return the current number of events waiting in the queue."""
        return self._queue.qsize()

    @property
    def events_written(self) -> int:
        """Return the total number of events successfully written to the store."""
        return self._events_written

    @property
    def events_dropped(self) -> int:
        """Return the total number of events dropped due to queue overflow."""
        return self._events_dropped

    def _consumer_loop(self) -> None:
        """Background consumer loop that drains the queue to the event store.

        Runs in a daemon thread. Processes events one at a time with
        fail-open error handling — a single bad event never stops the consumer.
        """
        while self._running:
            try:
                event = self._queue.get(timeout=self.flush_interval)

                # Sentinel value signals shutdown
                if event is None:
                    self._queue.task_done()
                    # Drain remaining events before exiting
                    self._drain_remaining()
                    return

                self._write_event(event)
                self._queue.task_done()

            except queue.Empty:
                continue
            except Exception as e:
                logger.opt(exception=True).warning(
                    "Event queue consumer error (fail-open): {error}",
                    error=str(e),
                )

        # Drain remaining on normal stop
        self._drain_remaining()

    def _drain_remaining(self) -> None:
        """Drain any remaining events from the queue on shutdown."""
        while True:
            try:
                event = self._queue.get_nowait()
                if event is not None:
                    self._write_event(event)
                self._queue.task_done()
            except queue.Empty:
                break

    def _write_event(self, event: AgentEvent) -> None:
        """Write a single event to the store with fail-open error handling."""
        try:
            self.store.append(event)
            with self._lock:
                self._events_written += 1
        except Exception as e:
            logger.opt(exception=True).warning(
                "Failed to write event {event_id} to store (fail-open): {error}",
                event_id=str(event.event_id),
                error=str(e),
            )
