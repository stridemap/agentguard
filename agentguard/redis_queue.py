"""Redis-backed event queue for production deployments.

Drop-in replacement for the in-memory EventQueue. Events survive
AgentGuard restarts and can be consumed by multiple worker pods.

Activated when AGENTGUARD_QUEUE_BACKEND=redis.

Usage:
    from agentguard.redis_queue import RedisEventQueue

    queue = RedisEventQueue(store=store, redis_url="redis://localhost:6379/0")
    queue.start()
    queue.enqueue(event)
    queue.stop()
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any

from agentguard.logging import logger
from agentguard.models import AgentEvent


class RedisEventQueue:
    """Redis list-backed event queue with background consumer thread.

    Events are serialized to JSON and pushed to a Redis list. A background
    daemon thread pops events and writes them to the EventStore.

    Provides the same interface as the in-memory EventQueue.

    Attributes:
        store: The EventStore backend.
        redis_url: Redis connection URL.
        queue_key: Redis list key name.
    """

    def __init__(
        self,
        store: Any,
        redis_url: str = "redis://localhost:6379/0",
        queue_key: str = "agentguard:events",
        max_size: int = 10_000,
        flush_interval: float = 0.1,
    ) -> None:
        self.store = store
        self.redis_url = redis_url
        self.queue_key = queue_key
        self.max_size = max_size
        self.flush_interval = flush_interval
        self._client = None
        self._consumer_thread: threading.Thread | None = None
        self._running = False
        self._events_written = 0
        self._events_dropped = 0
        self._lock = threading.Lock()

    def _get_client(self):
        """Lazily connect to Redis."""
        if self._client is None:
            import redis

            self._client = redis.from_url(self.redis_url)
        return self._client

    def start(self) -> None:
        """Start the background consumer thread."""
        if self._running:
            return

        self._running = True
        self._consumer_thread = threading.Thread(
            target=self._consumer_loop,
            name="agentguard-redis-consumer",
            daemon=True,
        )
        self._consumer_thread.start()
        logger.bind(module="agentguard.redis_queue").info(
            "Redis queue consumer started (url={url} key={key})",
            url=self.redis_url,
            key=self.queue_key,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Stop the consumer thread gracefully."""
        if not self._running:
            return

        self._running = False
        if self._consumer_thread is not None:
            self._consumer_thread.join(timeout=timeout)
            self._consumer_thread = None

        logger.bind(module="agentguard.redis_queue").info(
            "Redis queue consumer stopped (written={written}, dropped={dropped})",
            written=self._events_written,
            dropped=self._events_dropped,
        )

    def enqueue(self, event: AgentEvent) -> bool:
        """Push an event to the Redis list."""
        try:
            client = self._get_client()
            current_len = client.llen(self.queue_key)
            if current_len >= self.max_size:
                with self._lock:
                    self._events_dropped += 1
                logger.warning(
                    "Redis queue full — dropping event {event_id}",
                    event_id=str(event.event_id),
                )
                return False

            data = event.model_dump_json()
            client.rpush(self.queue_key, data)
            return True

        except Exception as e:
            with self._lock:
                self._events_dropped += 1
            logger.opt(exception=True).warning(
                "Redis enqueue error: {error}", error=str(e)
            )
            return False

    @property
    def queue_depth(self) -> int:
        try:
            client = self._get_client()
            return client.llen(self.queue_key)
        except Exception:
            return 0

    @property
    def events_written(self) -> int:
        return self._events_written

    @property
    def events_dropped(self) -> int:
        return self._events_dropped

    def _consumer_loop(self) -> None:
        """Background loop popping events from Redis and writing to store."""
        while self._running:
            try:
                client = self._get_client()
                data = client.lpop(self.queue_key)
                if data is None:
                    time.sleep(self.flush_interval)
                    continue

                event_dict = json.loads(data)
                event = AgentEvent.model_validate(event_dict)
                self.store.append(event)
                with self._lock:
                    self._events_written += 1

            except Exception as e:
                logger.opt(exception=True).warning(
                    "Redis consumer error (fail-open): {error}", error=str(e)
                )
                time.sleep(self.flush_interval)
