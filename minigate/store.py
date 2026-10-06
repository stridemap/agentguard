"""Audit sink for MiniGate.

Reuses AgentGuard's append-only event store and SHA-256 audit chain, so MiniGate
decisions land in the same tamper-evident log and the same dashboard as everything
else. Writes go through AgentGuard's background queue: a tool call must never wait
on disk I/O.
"""

from __future__ import annotations

from typing import Protocol

from agentguard.store_factory import create_store
from minigate.logging import logger
from minigate.models import McpEvent


class EventSink(Protocol):
    """Where governed events go. Implemented by AuditSink and, in tests, by a list."""

    def emit(self, event: McpEvent) -> None: ...


class NullSink:
    """Discards events. Used when auditing is disabled or the store cannot be opened."""

    def emit(self, event: McpEvent) -> None:  # noqa: D102
        return


class AuditSink:
    """Persists McpEvents to AgentGuard's audit chain via its non-blocking queue."""

    def __init__(self, database_url: str | None = None) -> None:
        from agentguard.event_store import EventQueue

        self._store = create_store(database_url)
        self._queue = EventQueue(store=self._store)
        self._queue.start()

    def emit(self, event: McpEvent) -> None:
        """Enqueue an event. Never raises — losing an audit record must not break the agent."""
        try:
            self._queue.enqueue(event.to_agent_event())
        except Exception as e:
            logger.bind(module="minigate.store").warning(
                "Failed to enqueue audit event (fail-open): {error}", error=str(e)
            )

    def close(self) -> None:
        """Drain the queue and close the store."""
        try:
            self._queue.stop()
            self._store.close()
        except Exception as e:
            logger.bind(module="minigate.store").warning(
                "Error closing audit sink: {error}", error=str(e)
            )


def create_sink(database_url: str | None) -> EventSink:
    """Build an audit sink, falling back to NullSink if the store cannot be opened."""
    try:
        return AuditSink(database_url)
    except Exception as e:
        logger.bind(module="minigate.store").warning(
            "Audit store unavailable, continuing without audit (fail-open): {error}",
            error=str(e),
        )
        return NullSink()
