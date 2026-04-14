"""Factory for creating the appropriate event store + queue backend.

Selects SQLite or PostgreSQL based on DATABASE_URL, and in-memory
queue or Redis based on AGENTGUARD_QUEUE_BACKEND.

Usage:
    from agentguard.store_factory import create_store, create_queue

    store = create_store()  # reads DATABASE_URL
    queue = create_queue(store)  # reads AGENTGUARD_QUEUE_BACKEND
"""

from __future__ import annotations

import os

from agentguard.event_store import EventQueue, EventStore
from agentguard.logging import logger


def create_store(db_url: str | None = None) -> EventStore:
    """Create an event store based on the database URL.

    Args:
        db_url: Database URL. If None, reads DATABASE_URL env var.
            - 'sqlite:///path' or plain path → SQLite
            - 'postgresql://...' → PostgreSQL

    Returns:
        An EventStore (SQLite) or PostgresEventStore instance.
    """
    if db_url is None:
        db_url = os.environ.get("DATABASE_URL", "sqlite:///agentguard.db")

    if db_url.startswith("postgresql"):
        from agentguard.pg_store import PostgresEventStore

        logger.bind(module="agentguard.store_factory").info(
            "Using PostgreSQL backend: {url}", url=db_url[:50] + "..."
        )
        return PostgresEventStore(dsn=db_url)  # type: ignore[return-value]

    # SQLite — strip 'sqlite:///' prefix if present
    db_path = db_url
    if db_path.startswith("sqlite:///"):
        db_path = db_path[len("sqlite:///") :]

    logger.bind(module="agentguard.store_factory").info(
        "Using SQLite backend: {path}", path=db_path
    )
    return EventStore(db_path=db_path)


def create_queue(
    store: EventStore,
    backend: str | None = None,
    redis_url: str | None = None,
) -> EventQueue:
    """Create an event queue with the specified backend.

    Args:
        store: The event store to flush events to.
        backend: 'memory' or 'redis'. If None, reads
            AGENTGUARD_QUEUE_BACKEND env var (default: 'memory').
        redis_url: Redis URL for the redis backend.

    Returns:
        An EventQueue (in-memory) or RedisEventQueue instance.
    """
    if backend is None:
        backend = os.environ.get("AGENTGUARD_QUEUE_BACKEND", "memory")

    if backend == "redis":
        if redis_url is None:
            redis_url = os.environ.get(
                "AGENTGUARD_REDIS_URL", "redis://localhost:6379/0"
            )

        from agentguard.redis_queue import RedisEventQueue

        logger.bind(module="agentguard.store_factory").info(
            "Using Redis queue backend: {url}", url=redis_url
        )
        return RedisEventQueue(store=store, redis_url=redis_url)  # type: ignore[return-value]

    logger.bind(module="agentguard.store_factory").info("Using in-memory queue backend")
    return EventQueue(store=store)
