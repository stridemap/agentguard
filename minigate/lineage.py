"""Data lineage across chained tool calls.

Per-call evaluation is structurally blind to the attack that matters most in an agent
workflow: read customer records from a trusted system, then write them into a public
ticket. Each call is individually permitted. Only the sequence is a breach.

The tracker marks values returned by a tool with the trust level of the server that
produced them, then checks the arguments of later calls against those marks. A value
that surfaces at a sink of lower trust than its source is a trust-boundary crossing.

**Only hashes are stored.** A taint store holding raw customer records would be a worse
liability than the leak it prevents, so values are normalised and SHA-256 hashed on the
way in, and outbound arguments are hashed the same way and compared. Matching is
therefore exact-on-extracted-values, not substring search — which is why extraction runs
several strategies, including the DLP scanner, whose entity matches catch a record
embedded in prose that structural extraction alone would miss.

**The store is shared across processes.** Each MiniGate process fronts one upstream
server, so an in-process store could only ever see same-server flows — and the valuable
case is cross-server. A SQLite store at a shared path lets every MiniGate process on the
machine contribute to and read the same lineage, with a TTL bounding how long a value
stays tainted.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum

from minigate.logging import logger

_QUOTED = re.compile(r'"([^"]{4,})"')
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/+-]{7,}")
_PURGE_INTERVAL_SECONDS = 300.0


class TrustLevel(IntEnum):
    """Ordered sensitivity of a data source or sink.

    Comparison is what defines a crossing, so the ordering is the whole contract:
    data may flow to equal or higher trust, never downward.
    """

    PUBLIC = 10
    INTERNAL = 20
    CONFIDENTIAL = 30
    RESTRICTED = 40

    @classmethod
    def parse(cls, value: str | int | None, default: TrustLevel | None = None) -> TrustLevel:
        """Resolve a config value to a level, accepting names or raw integers."""
        if value is None:
            return default if default is not None else cls.INTERNAL
        if isinstance(value, int) and not isinstance(value, bool):
            return cls(value) if value in {level.value for level in cls} else cls.INTERNAL
        try:
            return cls[str(value).strip().upper()]
        except KeyError:
            logger.bind(module="minigate.lineage").warning(
                "Unknown trust level {value!r} — defaulting to INTERNAL", value=value
            )
            return cls.INTERNAL


@dataclass(frozen=True)
class TaintMark:
    """Where a value came from."""

    source_server: str
    source_tool: str
    trust: TrustLevel
    event_id: str

    @property
    def source(self) -> str:
        return f"{self.source_server}.{self.source_tool}"


@dataclass
class LineageVerdict:
    """The outcome of checking one outbound payload."""

    crossings: list[TaintMark] = field(default_factory=list)

    @property
    def is_crossing(self) -> bool:
        return bool(self.crossings)

    @property
    def sources(self) -> list[str]:
        """Distinct source references, most sensitive first."""
        seen: dict[str, TrustLevel] = {}
        for mark in self.crossings:
            if mark.source not in seen or mark.trust > seen[mark.source]:
                seen[mark.source] = mark.trust
        return [src for src, _ in sorted(seen.items(), key=lambda kv: -kv[1])]

    def summary(self, sink: str, sink_trust: TrustLevel) -> str:
        highest = max((m.trust for m in self.crossings), default=sink_trust)
        return (
            f"data from {', '.join(self.sources)} ({highest.name}) "
            f"reaching {sink} ({sink_trust.name})"
        )


def normalize(value: str) -> str:
    """Collapse whitespace and case so trivial reformatting does not defeat matching."""
    return " ".join(value.split()).casefold()


def value_hash(value: str) -> str:
    """SHA-256 of a normalised value. The only form ever persisted."""
    return hashlib.sha256(normalize(value).encode()).hexdigest()


def extract_values(text: str, min_length: int = 8, limit: int = 200) -> set[str]:
    """Pull candidate values out of a payload.

    Several strategies, because agents move data in different shapes: JSON leaves for
    structured results, whole lines and quoted spans for prose, and distinctive tokens
    for the identifiers that survive being reformatted into a different sentence. Values
    shorter than `min_length` are dropped — matching on "true" or "id" would flag every
    call.
    """
    if not text:
        return set()

    candidates: set[str] = set()
    structured = False

    with contextlib.suppress(json.JSONDecodeError, RecursionError):
        _walk_json(json.loads(text), candidates)
        structured = True

    if not structured:
        # Line and quote extraction only for unstructured text. Running them over JSON
        # too would taint syntax fragments — a line like '"ok": true,' occurs in almost
        # any payload, so it would flag unrelated calls as crossings.
        for line in text.splitlines():
            stripped = line.strip()
            if stripped:
                candidates.add(stripped)
        candidates.update(_QUOTED.findall(text))

    kept = {normalize(c) for c in candidates}
    kept = {c for c in kept if len(c) >= min_length}

    # Tokens are capped separately from the bulk candidates: they are short by nature and
    # would be the first thing dropped, yet an account or contract reference is exactly
    # the value that gets copied verbatim from one system into another. The two caps make
    # the worst case 2 × limit, which is the intended bound.
    return _cap(kept, limit) | _cap(_distinctive_tokens(text), limit)


def _cap(values: set[str], limit: int) -> set[str]:
    """Keep the most distinctive values when a payload would otherwise flood the store.

    Longer values are more distinctive, so length leads — but ties break on the value
    itself. Without that tiebreak the surviving subset depends on set iteration order,
    which varies with the hash seed, and the same payload would taint differently on
    different runs. Detection has to be reproducible to be auditable.
    """
    if len(values) <= limit:
        return values
    return set(sorted(values, key=lambda v: (-len(v), v))[:limit])


def _distinctive_tokens(text: str) -> set[str]:
    """Identifier-shaped tokens: account numbers, contract refs, keys, UUIDs.

    Requiring both a digit and a letter is what keeps this from generating noise. Prose
    words carry no digits; bare dates and version numbers carry no letters; what remains
    is overwhelmingly machine-generated identifiers — precisely the class of value that
    moves verbatim between systems, and the one exact matching would otherwise miss when
    an agent rewrites the sentence around it.
    """
    tokens: set[str] = set()
    for match in _TOKEN.finditer(text):
        token = match.group(0).strip("._:-/+")
        if len(token) < 8:
            continue
        if any(c.isdigit() for c in token) and any(c.isalpha() for c in token):
            tokens.add(normalize(token))
    return tokens


def _walk_json(node: object, out: set[str], depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(node, dict):
        for item in node.values():
            _walk_json(item, out, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, out, depth + 1)
    elif isinstance(node, str):
        out.add(node)
    elif isinstance(node, (int, float)) and not isinstance(node, bool):
        out.add(str(node))


class TaintStore:
    """Shared, TTL-bounded store of tainted value hashes.

    Backed by SQLite so MiniGate processes fronting different servers observe the same
    lineage. Pass ':memory:' for a process-local store in tests.
    """

    _CREATE = """
    CREATE TABLE IF NOT EXISTS taint (
        value_hash TEXT PRIMARY KEY,
        source_server TEXT NOT NULL,
        source_tool TEXT NOT NULL,
        trust INTEGER NOT NULL,
        event_id TEXT NOT NULL,
        created_at REAL NOT NULL
    )
    """

    def __init__(self, path: str = ":memory:", ttl_seconds: float = 3600.0) -> None:
        self.path = path
        self.ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        self._last_purge = 0.0
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=5.0)
        if path != ":memory:":
            # WAL lets readers and a writer coexist across processes.
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute(self._CREATE)
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_taint_created ON taint(created_at)")
        self._conn.commit()

    def add(self, hashes: set[str], mark: TaintMark) -> int:
        """Record value hashes as originating from `mark`.

        On collision the more sensitive origin wins: a value seen from both an internal
        and a restricted source must be treated as restricted.
        """
        if not hashes:
            return 0
        now = time.time()
        rows = [
            (h, mark.source_server, mark.source_tool, int(mark.trust), mark.event_id, now)
            for h in hashes
        ]
        with self._lock:
            self._conn.executemany(
                """
                INSERT INTO taint (value_hash, source_server, source_tool, trust, event_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(value_hash) DO UPDATE SET
                    source_server = excluded.source_server,
                    source_tool   = excluded.source_tool,
                    trust         = excluded.trust,
                    event_id      = excluded.event_id,
                    created_at    = excluded.created_at
                WHERE excluded.trust >= taint.trust
                """,
                rows,
            )
            self._conn.commit()
            self._maybe_purge(now)
        return len(rows)

    def lookup(self, hashes: set[str], min_trust: int) -> list[TaintMark]:
        """Return marks for any of `hashes` recorded at a trust level above `min_trust`."""
        if not hashes:
            return []
        cutoff = time.time() - self.ttl_seconds
        found: list[TaintMark] = []
        ordered = list(hashes)
        with self._lock:
            for start in range(0, len(ordered), 400):
                chunk = ordered[start : start + 400]
                placeholders = ",".join("?" * len(chunk))
                rows = self._conn.execute(
                    f"""
                    SELECT source_server, source_tool, trust, event_id FROM taint
                    WHERE value_hash IN ({placeholders}) AND trust > ? AND created_at >= ?
                    """,  # noqa: S608 — placeholders are generated, values are bound
                    (*chunk, min_trust, cutoff),
                ).fetchall()
                found.extend(
                    TaintMark(
                        source_server=r[0],
                        source_tool=r[1],
                        trust=TrustLevel(r[2]),
                        event_id=r[3],
                    )
                    for r in rows
                )
        return found

    def _maybe_purge(self, now: float) -> None:
        """Drop expired marks periodically. Caller holds the lock."""
        if now - self._last_purge < _PURGE_INTERVAL_SECONDS:
            return
        self._last_purge = now
        self._conn.execute("DELETE FROM taint WHERE created_at < ?", (now - self.ttl_seconds,))
        self._conn.commit()

    def count(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM taint").fetchone()[0]

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class LineageTracker:
    """Marks values from tool results and detects trust-boundary crossings.

    Every method is fail-open: a tracker that throws must not break the agent, so
    failures degrade to "no crossing detected" and are logged.
    """

    def __init__(
        self,
        store: TaintStore | None = None,
        min_value_length: int = 8,
        max_values_per_result: int = 200,
    ) -> None:
        self.store = store or TaintStore()
        self.min_value_length = min_value_length
        self.max_values_per_result = max_values_per_result

    def record(
        self,
        text: str,
        *,
        server: str,
        tool: str,
        trust: TrustLevel,
        event_id: str,
        extra_values: list[str] | None = None,
    ) -> int:
        """Taint the values in a tool result with their source's trust level.

        Args:
            text: The result content.
            server: Source server name.
            tool: Source tool name.
            trust: Trust level of the source.
            event_id: Audit event this result belongs to.
            extra_values: Additional values to taint regardless of length — DLP entity
                matches, which are distinctive even when short.

        Returns:
            How many value hashes were recorded.
        """
        try:
            values = extract_values(text, self.min_value_length, self.max_values_per_result)
            values.update(normalize(v) for v in (extra_values or []) if normalize(v))
            hashes = {value_hash(v) for v in values}
            mark = TaintMark(
                source_server=server, source_tool=tool, trust=trust, event_id=event_id
            )
            return self.store.add(hashes, mark)
        except Exception as e:
            logger.bind(module="minigate.lineage").warning(
                "Could not record lineage (fail-open): {error}", error=str(e)
            )
            return 0

    def check(
        self, text: str, *, sink_trust: TrustLevel, extra_values: list[str] | None = None
    ) -> LineageVerdict:
        """Check an outbound payload for values that came from a more trusted source."""
        try:
            values = extract_values(text, self.min_value_length, self.max_values_per_result)
            values.update(normalize(v) for v in (extra_values or []) if normalize(v))
            hashes = {value_hash(v) for v in values}
            return LineageVerdict(crossings=self.store.lookup(hashes, int(sink_trust)))
        except Exception as e:
            logger.bind(module="minigate.lineage").warning(
                "Could not check lineage (fail-open): {error}", error=str(e)
            )
            return LineageVerdict()
