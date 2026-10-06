"""A persistent, encrypted `GrantStore`.

The in-memory store loses every grant on restart, which means a deploy logs every user
out. This one survives, and because what it persists is third-party access tokens, the
rows are encrypted rather than merely stored.

**Encryption is at the row level, not the column.** The whole token set — access token,
refresh token, scope, expiry — is serialised and sealed with Fernet (AES-128-CBC with an
HMAC-SHA256 authentication tag). A database backup, a replica, or a stolen dump yields
ciphertext, and the key lives only in the process environment. That is meaningfully
weaker than a managed KMS and meaningfully stronger than plaintext; the honest framing is
that it defends against disclosure of the data at rest, not against compromise of the
running host, which holds the key.

Backend follows the audit store's convention: SQLite for local and development,
PostgreSQL when the URL says so. The schema is deliberately identical across both, with
only the parameter style differing.

Expired sessions, codes and grants are deleted rather than left to accumulate. Retaining
a live upstream credential past the point anything can use it is pure liability.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any

from minigate.bridge_store import (
    _CODE_TTL_SECONDS,
    _SESSION_TTL_SECONDS,
    AuthSession,
    Grant,
    RegisteredClient,
    UpstreamClient,
)
from minigate.logging import logger
from minigate.oauth_client import TokenSet

_KEY_ENV = "MINIGATE_GRANT_KEY"
_PURGE_INTERVAL_SECONDS = 60.0

__all__ = ["SqlGrantStore", "StoreKeyError", "generate_key"]


class StoreKeyError(Exception):
    """Raised when the encryption key is missing or unusable."""


def generate_key() -> str:
    """A fresh Fernet key, for `MINIGATE_GRANT_KEY`."""
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


def _load_cipher(key: str | None):
    """Build the cipher, refusing to start without a usable key.

    This is the one place in MiniGate that fails closed on a configuration error. Every
    other degradation is fail-open by design, because a broken control must not break the
    agent — but silently falling back to plaintext storage of other people's access
    tokens is not a degradation anyone would accept by default.
    """
    from cryptography.fernet import Fernet

    material = key or os.environ.get(_KEY_ENV)
    if not material:
        msg = (
            f"{_KEY_ENV} is not set. Generate one with "
            f"`python -c \"from minigate.bridge_sql_store import generate_key; print(generate_key())\"` "
            f"and set it in the environment. Grants are not stored unencrypted."
        )
        raise StoreKeyError(msg)
    try:
        return Fernet(material.encode() if isinstance(material, str) else material)
    except Exception as e:
        msg = f"{_KEY_ENV} is not a valid Fernet key: {e}"
        raise StoreKeyError(msg) from e


_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS bridge_clients (
    client_id     TEXT PRIMARY KEY,
    redirect_uris TEXT NOT NULL,
    client_name   TEXT NOT NULL,
    created_at    REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS bridge_upstream_clients (
    server_name TEXT PRIMARY KEY,
    client_id   TEXT NOT NULL,
    sealed      BLOB,
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS bridge_sessions (
    session_id TEXT PRIMARY KEY,
    sealed     BLOB NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS bridge_grants (
    grant_id     TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    server_name  TEXT NOT NULL,
    code          TEXT UNIQUE,
    access_token  TEXT UNIQUE,
    refresh_token TEXT UNIQUE,
    sealed        BLOB NOT NULL,
    created_at    REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bridge_grants_code ON bridge_grants(code);
CREATE INDEX IF NOT EXISTS idx_bridge_grants_token ON bridge_grants(access_token);
CREATE INDEX IF NOT EXISTS idx_bridge_grants_refresh ON bridge_grants(refresh_token);
"""

_PG_SCHEMA = _SQLITE_SCHEMA.replace("BLOB", "BYTEA")


class SqlGrantStore:
    """A `GrantStore` backed by SQLite or PostgreSQL, with grants encrypted at rest."""

    def __init__(self, database_url: str | None = None, key: str | None = None) -> None:
        self._cipher = _load_cipher(key)
        self._lock = threading.Lock()
        self._last_purge = 0.0
        url = database_url or "minigate-grants.db"
        self._is_pg = url.startswith(("postgres://", "postgresql://"))

        if self._is_pg:
            import psycopg2

            self._conn = psycopg2.connect(url)
            self._conn.autocommit = True
            self._ph = "%s"
            schema = _PG_SCHEMA
        else:
            import sqlite3

            self._conn = sqlite3.connect(url, check_same_thread=False, timeout=5.0)
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._ph = "?"
            schema = _SQLITE_SCHEMA

        with self._lock:
            cur = self._conn.cursor()
            for statement in filter(None, (s.strip() for s in schema.split(";"))):
                cur.execute(statement)
            if not self._is_pg:
                self._conn.commit()
        logger.bind(module="minigate.bridge").info(
            "Grant store ready ({backend}, encrypted)",
            backend="postgresql" if self._is_pg else "sqlite",
        )

    # ── sealing ──────────────────────────────────────────────────────

    def _seal(self, payload: dict[str, Any]) -> bytes:
        return self._cipher.encrypt(json.dumps(payload).encode())

    def _open(self, sealed: Any) -> dict[str, Any]:
        if isinstance(sealed, memoryview):
            sealed = sealed.tobytes()
        return json.loads(self._cipher.decrypt(bytes(sealed)))

    def _q(self, sql: str) -> str:
        return sql.replace("?", self._ph) if self._is_pg else sql

    def _execute(self, sql: str, params: tuple = ()) -> list[tuple]:
        with self._lock:
            self._maybe_purge()
            cur = self._conn.cursor()
            cur.execute(self._q(sql), params)
            rows = cur.fetchall() if cur.description else []
            if not self._is_pg:
                self._conn.commit()
            return rows

    # ── clients ──────────────────────────────────────────────────────

    def put_client(self, client: RegisteredClient) -> None:
        self._execute(
            "INSERT INTO bridge_clients (client_id, redirect_uris, client_name, created_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT (client_id) DO NOTHING",
            (client.client_id, json.dumps(list(client.redirect_uris)),
             client.client_name, client.created_at),
        )

    def get_client(self, client_id: str) -> RegisteredClient | None:
        rows = self._execute(
            "SELECT client_id, redirect_uris, client_name, created_at "
            "FROM bridge_clients WHERE client_id = ?",
            (client_id,),
        )
        if not rows:
            return None
        cid, uris, name, created = rows[0]
        return RegisteredClient(
            client_id=cid, redirect_uris=tuple(json.loads(uris)),
            client_name=name, created_at=created,
        )

    def count_clients(self) -> int:
        rows = self._execute("SELECT COUNT(*) FROM bridge_clients")
        return int(rows[0][0]) if rows else 0

    def purge_unused_clients(self, before: float) -> int:
        """Drop old clients that never completed an authorization."""
        rows = self._execute(
            "SELECT COUNT(*) FROM bridge_clients WHERE created_at < ? "
            "AND client_id NOT IN (SELECT client_id FROM bridge_grants)",
            (before,),
        )
        removed = int(rows[0][0]) if rows else 0
        self._execute(
            "DELETE FROM bridge_clients WHERE created_at < ? "
            "AND client_id NOT IN (SELECT client_id FROM bridge_grants)",
            (before,),
        )
        return removed

    # ── upstream registration ────────────────────────────────────────

    def put_upstream_client(self, client: UpstreamClient) -> None:
        # The secret, where one exists, is MiniGate's own credential with the vendor.
        sealed = self._seal({"client_secret": client.client_secret})
        self._execute(
            "INSERT INTO bridge_upstream_clients (server_name, client_id, sealed, created_at) "
            "VALUES (?, ?, ?, ?) ON CONFLICT (server_name) DO UPDATE SET "
            "client_id = EXCLUDED.client_id, sealed = EXCLUDED.sealed",
            (client.server_name, client.client_id, sealed, client.created_at),
        )

    def get_upstream_client(self, server_name: str) -> UpstreamClient | None:
        rows = self._execute(
            "SELECT server_name, client_id, sealed, created_at "
            "FROM bridge_upstream_clients WHERE server_name = ?",
            (server_name,),
        )
        if not rows:
            return None
        name, client_id, sealed, created_at = rows[0]
        secret = self._open(sealed).get("client_secret") if sealed else None
        return UpstreamClient(
            server_name=name, client_id=client_id,
            client_secret=secret, created_at=created_at,
        )

    # ── sessions ─────────────────────────────────────────────────────

    def put_session(self, session: AuthSession) -> None:
        # The verifier is a credential for the upstream leg, so the row is sealed.
        self._execute(
            "INSERT INTO bridge_sessions (session_id, sealed, created_at) VALUES (?, ?, ?)",
            (session.session_id, self._seal({
                "client_id": session.client_id,
                "server_name": session.server_name,
                "client_redirect_uri": session.client_redirect_uri,
                "client_state": session.client_state,
                "client_code_challenge": session.client_code_challenge,
                "client_code_challenge_method": session.client_code_challenge_method,
                "upstream_verifier": session.upstream_verifier,
            }), session.created_at),
        )

    def take_session(self, session_id: str) -> AuthSession | None:
        rows = self._execute(
            "SELECT sealed, created_at FROM bridge_sessions WHERE session_id = ?", (session_id,)
        )
        self._execute("DELETE FROM bridge_sessions WHERE session_id = ?", (session_id,))
        if not rows:
            return None
        sealed, created_at = rows[0]
        if time.time() - created_at > _SESSION_TTL_SECONDS:
            return None
        return AuthSession(session_id=session_id, created_at=created_at, **self._open(sealed))

    # ── grants ───────────────────────────────────────────────────────

    def put_grant(self, grant: Grant) -> None:
        sealed = self._seal({
            "access_token": grant.upstream.access_token,
            "token_type": grant.upstream.token_type,
            "refresh_token": grant.upstream.refresh_token,
            "expires_in": grant.upstream.expires_in,
            "scope": grant.upstream.scope,
            "code_challenge": grant.code_challenge,
            "code_challenge_method": grant.code_challenge_method,
            "redirect_uri": grant.redirect_uri,
            "access_expires_at": grant.access_expires_at,
            "upstream_expires_at": grant.upstream_expires_at,
            "subject": grant.subject,
            "subject_email": grant.subject_email,
        })
        self._execute(
            "INSERT INTO bridge_grants "
            "(grant_id, client_id, server_name, code, access_token, refresh_token, "
            " sealed, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (grant_id) DO UPDATE SET code = EXCLUDED.code, "
            "access_token = EXCLUDED.access_token, "
            "refresh_token = EXCLUDED.refresh_token, sealed = EXCLUDED.sealed",
            (grant.grant_id, grant.client_id, grant.server_name, grant.code,
             grant.access_token, grant.refresh_token, sealed, grant.created_at),
        )

    def _hydrate(self, row: tuple) -> Grant:
        (grant_id, client_id, server_name, code, access_token,
         refresh_token, sealed, created_at) = row
        data = self._open(sealed)
        return Grant(
            grant_id=grant_id, client_id=client_id, server_name=server_name,
            upstream=TokenSet(
                access_token=data["access_token"], token_type=data["token_type"],
                refresh_token=data.get("refresh_token"), expires_in=data.get("expires_in"),
                scope=data.get("scope"),
            ),
            code=code, access_token=access_token, refresh_token=refresh_token,
            access_expires_at=data.get("access_expires_at"),
            upstream_expires_at=data.get("upstream_expires_at"),
            subject=data.get("subject"),
            subject_email=data.get("subject_email"),
            code_challenge=data.get("code_challenge"),
            code_challenge_method=data.get("code_challenge_method", "S256"),
            redirect_uri=data.get("redirect_uri"),
            created_at=created_at,
        )

    _SELECT = (
        "SELECT grant_id, client_id, server_name, code, access_token, refresh_token, "
        "sealed, created_at FROM bridge_grants WHERE "
    )

    def take_by_code(self, code: str) -> Grant | None:
        rows = self._execute(self._SELECT + "code = ?", (code,))
        # Clear the code whether or not it was valid: a reuse attempt means it leaked.
        self._execute("UPDATE bridge_grants SET code = NULL WHERE code = ?", (code,))
        if not rows:
            return None
        grant = self._hydrate(rows[0])
        return None if grant.code_is_expired() else grant

    def get_by_access_token(self, access_token: str) -> Grant | None:
        rows = self._execute(self._SELECT + "access_token = ?", (access_token,))
        return self._hydrate(rows[0]) if rows else None

    def get_by_refresh_token(self, refresh_token: str) -> Grant | None:
        rows = self._execute(self._SELECT + "refresh_token = ?", (refresh_token,))
        return self._hydrate(rows[0]) if rows else None

    def revoke(self, access_token: str) -> bool:
        """Delete the whole grant, not just the access token.

        Leaving the refresh token able to mint a replacement is not revocation.
        """
        existed = bool(self._execute(self._SELECT + "access_token = ?", (access_token,)))
        self._execute("DELETE FROM bridge_grants WHERE access_token = ?", (access_token,))
        return existed

    # ── housekeeping ─────────────────────────────────────────────────

    def _maybe_purge(self) -> None:
        """Delete what nothing can use. Called under the lock.

        An unredeemed code or an abandoned session is dead weight; a grant past its
        useful life is a live third-party credential nobody is going to use again.
        """
        now = time.time()
        if now - self._last_purge < _PURGE_INTERVAL_SECONDS:
            return
        self._last_purge = now
        cur = self._conn.cursor()
        cur.execute(
            self._q("DELETE FROM bridge_sessions WHERE created_at < ?"),
            (now - _SESSION_TTL_SECONDS,),
        )
        cur.execute(
            self._q(
                "UPDATE bridge_grants SET code = NULL "
                "WHERE code IS NOT NULL AND created_at < ?"
            ),
            (now - _CODE_TTL_SECONDS,),
        )
        cur.execute(
            self._q(
                "DELETE FROM bridge_grants WHERE access_token IS NULL AND code IS NULL "
                "AND refresh_token IS NULL AND created_at < ?"
            ),
            (now - _SESSION_TTL_SECONDS,),
        )
        if not self._is_pg:
            self._conn.commit()

    @property
    def counts(self) -> dict[str, int]:
        def one(sql: str) -> int:
            rows = self._execute(sql)
            return int(rows[0][0]) if rows else 0

        return {
            "clients": one("SELECT COUNT(*) FROM bridge_clients"),
            "sessions": one("SELECT COUNT(*) FROM bridge_sessions"),
            "grants": one("SELECT COUNT(*) FROM bridge_grants WHERE access_token IS NOT NULL"),
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
