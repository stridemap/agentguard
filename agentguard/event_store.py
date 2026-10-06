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
import hashlib
import json
import queue
import sqlite3
import threading
import time
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
    latency_ms, risk_flags, policy_result, prev_hash, event_hash
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class EventStore:
    """Append-only SQLite event store.

    All writes go through append(). No UPDATE or DELETE operations are
    exposed. The database schema is auto-created on initialization.

    Attributes:
        db_path: Path to the SQLite database file.
    """

    _GENESIS_HASH = "0" * 64

    def __init__(self, db_path: str = "agentguard.db") -> None:
        """Initialize the event store and create the schema.

        Args:
            db_path: Path to the SQLite database file. Use ":memory:" for tests.
        """
        self.db_path = db_path
        self._local = threading.local()
        self._chain_lock = threading.Lock()
        self._last_hash: str = self._GENESIS_HASH
        self._init_db()
        self._resume_chain()

    def _resume_chain(self) -> None:
        """Restore _last_hash from the most recently appended event.

        Without this, a new EventStore opened against an existing DB would
        start its first append() with prev_hash=GENESIS, breaking the
        cryptographic chain at that row. Resuming makes the chain durable
        across process restarts.
        """
        row = self._get_conn().execute(
            "SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        if row is not None:
            self._last_hash = row[0]

    def _get_conn(self) -> sqlite3.Connection:
        """Return a thread-local SQLite connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            # isolation_level=None puts the driver in autocommit mode so append() can
            # open its own BEGIN IMMEDIATE transaction explicitly. busy_timeout makes a
            # competing writer wait for the lock instead of raising "database is locked".
            self._local.conn = sqlite3.connect(self.db_path, isolation_level=None, timeout=10.0)
            # busy_timeout must come first. It governs every statement after it, and the
            # very next one — switching to WAL — takes a brief exclusive lock. Set the
            # other way round, two stores opening the same file at once raced and one
            # raised "database is locked" from inside __init__, killing the writer before
            # it recorded anything.
            self._local.conn.execute("PRAGMA busy_timeout=10000")
            # Journal mode is a persistent property of the database, so under contention
            # it is enough that one connection wins: the rest inherit WAL. Losing the
            # race is not an error worth failing a connection over — WAL is a concurrency
            # optimisation, while the chain's integrity comes from BEGIN IMMEDIATE.
            with contextlib.suppress(sqlite3.OperationalError):
                self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn

    def _init_db(self) -> None:
        """Create the events table if it doesn't exist."""
        conn = self._get_conn()
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()

    @staticmethod
    def _compute_event_hash(event_data: dict, prev_hash: str) -> str:
        """Compute SHA-256 hash for an event including the previous hash.

        hash = SHA-256(json(event_fields, sort_keys=True) + prev_hash)
        """
        content = json.dumps(event_data, sort_keys=True) + prev_hash
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def append(self, event: AgentEvent) -> None:
        """Append a single event to the store with cryptographic chaining.

        Each event's hash includes the previous event's hash, forming
        a tamper-evident chain. Any modification to any past event
        breaks the chain from that point forward.

        This is the only write operation. No UPDATE or DELETE is allowed.

        Args:
            event: A finalized AgentEvent to persist.
        """
        with self._chain_lock:
            event_data = {
                "event_id": str(event.event_id),
                "timestamp": event.timestamp.isoformat(),
                "agent_id": event.agent_id,
                "session_id": event.session_id,
                "tool_name": event.tool_name,
                "input_hash": event.input_hash,
                "output_hash": event.output_hash,
                "latency_ms": event.latency_ms,
                "risk_flags": event.risk_flags,
                "policy_result": event.policy_result,
            }
            conn = self._get_conn()

            # BEGIN IMMEDIATE takes the write lock before the read, so the tip cannot
            # change between reading it and inserting. Reading from the database rather
            # than from in-memory state is what makes the chain correct when several
            # processes share one store — each holds its own _last_hash, and two of them
            # resuming from the same tip is exactly how the chain forks.
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute(
                    "SELECT event_hash FROM events ORDER BY rowid DESC LIMIT 1"
                ).fetchone()
                prev_hash = row[0] if row is not None else self._GENESIS_HASH
                event_hash = self._compute_event_hash(event_data, prev_hash)

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
                        prev_hash,
                        event_hash,
                    ),
                )
            except Exception:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")
            self._last_hash = event_hash

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

    def verify_chain(self) -> dict[str, Any]:
        """Verify the integrity of the cryptographic audit chain.

        Iterates all events in insertion order, recomputes each event's
        hash, and verifies it matches the stored hash. Any modification
        to any past event breaks the chain at that point.

        Returns:
            Dict with is_valid, total_events, first_tampered_event_id,
            and verification_latency_ms.
        """
        start = time.perf_counter()
        conn = self._get_conn()
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM events ORDER BY rowid ASC").fetchall()

        prev_hash = self._GENESIS_HASH
        for row in rows:
            event_data = {
                "event_id": row["event_id"],
                "timestamp": row["timestamp"],
                "agent_id": row["agent_id"],
                "session_id": row["session_id"],
                "tool_name": row["tool_name"],
                "input_hash": row["input_hash"],
                "output_hash": row["output_hash"],
                "latency_ms": row["latency_ms"],
                "risk_flags": (
                    json.loads(row["risk_flags"]) if row["risk_flags"] else []
                ),
                "policy_result": row["policy_result"],
            }
            expected_hash = self._compute_event_hash(event_data, prev_hash)

            if row["event_hash"] != expected_hash:
                return {
                    "is_valid": False,
                    "total_events": len(rows),
                    "first_tampered_event_id": row["event_id"],
                    "verification_latency_ms": (time.perf_counter() - start) * 1000,
                }

            prev_hash = row["event_hash"]

        return {
            "is_valid": True,
            "total_events": len(rows),
            "first_tampered_event_id": None,
            "verification_latency_ms": (time.perf_counter() - start) * 1000,
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
