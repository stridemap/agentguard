"""PostgreSQL event store backend for production deployments.

Drop-in replacement for the SQLite EventStore. Same append-only design,
same SHA-256 audit chain, but uses asyncpg connection pool for
high-throughput concurrent writes.

Activated when DATABASE_URL starts with 'postgresql'.

Usage:
    from agentguard.pg_store import PostgresEventStore

    store = PostgresEventStore("postgresql+asyncpg://user:pass@localhost:5432/agentguard")
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from typing import Any

from agentguard.logging import logger
from agentguard.models import AgentEvent

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
    -- DOUBLE PRECISION, not REAL. Postgres REAL is float4: it stores 4 bytes and
    -- returns a rounded value, while the chain hash is computed over the float8
    -- Python measured. The two never agree, so every verification failed at row 1.
    -- SQLite is unaffected — its REAL is an 8-byte IEEE double.
    latency_ms DOUBLE PRECISION,
    risk_flags TEXT NOT NULL,
    policy_result TEXT NOT NULL,
    prev_hash TEXT NOT NULL DEFAULT '',
    event_hash TEXT NOT NULL DEFAULT ''
)
"""

_CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events (agent_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_session_id ON events (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_events_tool_name ON events (tool_name)",
    "CREATE INDEX IF NOT EXISTS idx_events_risk_flags ON events (risk_flags)",
]

_INSERT_EVENT_SQL = """
INSERT INTO events (
    event_id, timestamp, agent_id, session_id, tool_name,
    run_id, parent_run_id, input_hash, output_hash,
    latency_ms, risk_flags, policy_result, prev_hash, event_hash
) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (event_id) DO NOTHING
"""


_CHAIN_LOCK_KEY = (
    0x41475F4348414E  # "AG_CHAN" — advisory lock namespace for the audit chain
)


class PostgresEventStore:
    """Append-only PostgreSQL event store with asyncpg connection pool.

    Provides the same interface as the SQLite EventStore for seamless
    switching via the factory function.

    Attributes:
        dsn: PostgreSQL connection string.
    """

    _GENESIS_HASH = "0" * 64

    def __init__(self, dsn: str) -> None:
        """Initialize the PostgreSQL event store.

        Args:
            dsn: PostgreSQL DSN (e.g. postgresql://user:pass@host:5432/db).
                 Strips '+asyncpg' suffix if present for psycopg2 compat.
        """
        # Normalize DSN — remove +asyncpg for sync driver
        self.dsn = dsn.replace("+asyncpg", "").replace("postgresql://", "postgresql://")
        self._conn = None
        self._chain_lock = threading.Lock()
        self._last_hash: str = self._GENESIS_HASH
        self._init_db()
        self._resume_chain()

    def _resume_chain(self) -> None:
        """Restore _last_hash from the most recently appended event.

        Without this, a new PgEventStore opened against an existing DB
        would start its first append() with prev_hash=GENESIS, breaking
        the cryptographic chain at that row. Critical in multi-worker
        deployments where each FastAPI process constructs its own store.

        Ordering matches verify_chain() (timestamp ASC), so "last" means
        max(timestamp). The companion SQLite store uses rowid because
        SQLite has no native insertion-time column.
        """
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT event_hash FROM events ORDER BY timestamp DESC LIMIT 1")
        row = cur.fetchone()
        if row is not None:
            self._last_hash = row[0]

    def _get_conn(self):
        """Get or create a psycopg2/pg8000 connection.

        Falls back to sqlite3-style interface using psycopg2.
        """
        if self._conn is None:
            try:
                import psycopg2

                self._conn = psycopg2.connect(self.dsn)
                self._conn.autocommit = False
            except ImportError as e:
                msg = (
                    "psycopg2 not installed. Install with: pip install psycopg2-binary"
                )
                raise ImportError(msg) from e
        return self._conn

    def _init_db(self) -> None:
        """Create the events table and indexes if they don't exist."""
        try:
            conn = self._get_conn()
            cur = conn.cursor()
            cur.execute(_CREATE_TABLE_SQL)
            for idx_sql in _CREATE_INDEXES_SQL:
                cur.execute(idx_sql)
            conn.commit()
            logger.bind(module="agentguard.pg_store").info(
                "PostgreSQL event store initialized: {dsn}", dsn=self.dsn[:50] + "..."
            )
        except Exception as e:
            logger.opt(exception=True).warning(
                "PostgreSQL init failed: {error}", error=str(e)
            )
            raise

    @staticmethod
    def _compute_event_hash(event_data: dict, prev_hash: str) -> str:
        """Compute SHA-256 hash for audit chain (same as SQLite store)."""
        content = json.dumps(event_data, sort_keys=True) + prev_hash
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def append(self, event: AgentEvent) -> None:
        """Append a single event with cryptographic chaining."""
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
            cur = conn.cursor()

            # A transaction-scoped advisory lock serialises appenders across every
            # process and worker sharing this database. An ordinary SELECT ... FOR UPDATE
            # would not do: on an empty table there is no row to lock, so two writers
            # would both read the genesis tip and fork the chain. The lock releases at
            # COMMIT or ROLLBACK.
            cur.execute("SELECT pg_advisory_xact_lock(%s)", (_CHAIN_LOCK_KEY,))
            cur.execute("SELECT event_hash FROM events ORDER BY timestamp DESC LIMIT 1")
            tip = cur.fetchone()
            prev_hash = tip[0] if tip is not None else self._GENESIS_HASH
            event_hash = self._compute_event_hash(event_data, prev_hash)

            cur.execute(
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
            conn.commit()
            self._last_hash = event_hash

    def get_event_count(self) -> int:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM events")
        row = cur.fetchone()
        return row[0] if row else 0

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM events WHERE event_id = %s", (event_id,))
        row = cur.fetchone()
        if row is None:
            return None
        columns = [desc[0] for desc in cur.description]
        return dict(zip(columns, row, strict=False))

    def get_events(self, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM events ORDER BY timestamp ASC LIMIT %s OFFSET %s",
            (limit, offset),
        )
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        return [dict(zip(columns, row, strict=False)) for row in rows]

    def verify_chain(self) -> dict[str, Any]:
        """Verify the cryptographic audit chain integrity."""
        start = time.perf_counter()
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT * FROM events ORDER BY timestamp ASC")
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]

        prev_hash = self._GENESIS_HASH
        for row_tuple in rows:
            row = dict(zip(columns, row_tuple, strict=False))
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
                    json.loads(row["risk_flags"])
                    if isinstance(row["risk_flags"], str)
                    else row["risk_flags"]
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

    def health_check(self) -> dict[str, Any]:
        try:
            count = self.get_event_count()
            return {"status": "healthy", "db_type": "postgresql", "event_count": count}
        except Exception as e:
            return {"status": "unhealthy", "db_type": "postgresql", "error": str(e)}

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None
