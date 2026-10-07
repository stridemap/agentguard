"""State for the OAuth bridge: registered clients, in-flight flows, and issued grants.

The bridge makes MiniGate an authorization server to its clients and an OAuth client to
each upstream, which means it holds three short-lived kinds of state:

  * **Clients** — who registered with us, and where we may redirect them back to.
  * **Sessions** — an authorization in flight, from our `/authorize` until the upstream
    sends the user back to our callback. Holds our PKCE verifier for the upstream leg
    and the client's challenge for ours.
  * **Grants** — a completed authorization: the upstream's tokens, plus whatever we
    issued to the client.

Storage is behind `GrantStore` so the in-memory implementation here can be replaced by a
persistent, encrypted one without touching the endpoints. That boundary is the point:
persistence is where the security review belongs, and keeping it separable means the
flow can be proven before the risky part is written.

Nothing here writes to disk. Restarting the gateway forgets every grant, and clients
re-consent. That is a deliberate property of this first implementation, not an oversight.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Protocol

from minigate.logging import logger
from minigate.oauth_client import TokenSet

_SESSION_TTL_SECONDS = 600.0
"""How long a user has to complete consent before the in-flight session is dropped."""

_CODE_TTL_SECONDS = 60.0
"""RFC 6749 §4.1.2 recommends an authorization code lifetime of under ten minutes;
one minute is ample for a client that redeems it immediately, and narrows the window
in which a leaked code is useful."""

_UNUSED_CLIENT_TTL_SECONDS = 7 * 24 * 3600.0
"""How long a registered client that never completed an authorization is kept.

Registration is open, so anyone can create one. A client that has never been through
consent holds nothing and is indistinguishable from litter after a week."""

_REFRESH_MARGIN_SECONDS = 120.0
"""Refresh an upstream token this long before it expires, so an in-flight call is not
racing the expiry."""

__all__ = [
    "AuthSession",
    "Grant",
    "GrantStore",
    "InMemoryGrantStore",
    "RegisteredClient",
    "UpstreamClient",
    "new_token",
]


def new_token(nbytes: int = 32) -> str:
    """A URL-safe random credential."""
    return secrets.token_urlsafe(nbytes)


@dataclass(frozen=True)
class UpstreamClient:
    """MiniGate's own registration with one upstream's authorization server.

    Persisted so a restart reuses it. Re-registering on every boot mints a fresh
    client_id each time, which litters the vendor's records and is a plausible way to be
    rate-limited by them.
    """

    server_name: str
    client_id: str
    client_secret: str | None = None
    created_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class RegisteredClient:
    """A client that registered with MiniGate's authorization server."""

    client_id: str
    redirect_uris: tuple[str, ...]
    client_name: str = "unknown"
    created_at: float = field(default_factory=time.time)

    def allows(self, redirect_uri: str) -> bool:
        """Whether a redirect target was registered.

        Exact match only. Prefix or wildcard matching on redirect URIs is how open
        redirectors are built, and an open redirector on an authorization server hands
        out authorization codes.
        """
        return redirect_uri in self.redirect_uris


@dataclass
class AuthSession:
    """An authorization in flight, from our /authorize to our callback."""

    session_id: str
    client_id: str
    server_name: str
    client_redirect_uri: str
    client_state: str | None
    client_code_challenge: str | None
    client_code_challenge_method: str
    upstream_verifier: str
    created_at: float = field(default_factory=time.time)

    def is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) - self.created_at > _SESSION_TTL_SECONDS


@dataclass
class Grant:
    """A completed authorization: the upstream's tokens, and what we issued for them.

    Two token lifetimes run here and they are independent. Ours governs what the client
    may present to the gateway; the upstream's governs what the gateway may present to
    the vendor. Conflating them produces either a client logged out while its upstream
    credential is still good, or a client holding a token whose upstream half died
    silently. They are tracked separately for that reason.
    """

    grant_id: str
    client_id: str
    server_name: str
    upstream: TokenSet
    code: str | None = None
    code_challenge: str | None = None
    code_challenge_method: str = "S256"
    redirect_uri: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    """Ours, issued to the client — never the upstream's."""
    access_expires_at: float | None = None
    upstream_expires_at: float | None = None
    subject: str | None = None
    """Stable identifier of the human who consented, from the upstream's id_token."""
    subject_email: str | None = None

    @property
    def principal(self) -> str:
        """Who to attribute an action to.

        The human where one is known, the client otherwise. An audit line reading
        `alice@acme.com` answers a different question from one reading `client_8f2a` —
        the second only tells you which integration, never which person.
        """
        return self.subject_email or self.subject or f"client:{self.client_id}"
    created_at: float = field(default_factory=time.time)

    def code_is_expired(self, now: float | None = None) -> bool:
        return (now or time.time()) - self.created_at > _CODE_TTL_SECONDS

    def access_is_expired(self, now: float | None = None) -> bool:
        if self.access_expires_at is None:
            return False
        return (now or time.time()) >= self.access_expires_at

    def upstream_needs_refresh(self, now: float | None = None) -> bool:
        """Whether the upstream credential is at or near expiry.

        Refreshed early, by a margin, so a call does not fail on a token that expires
        between the check and the upstream receiving it.
        """
        if self.upstream_expires_at is None:
            return False
        return (now or time.time()) >= self.upstream_expires_at - _REFRESH_MARGIN_SECONDS

    def can_refresh_upstream(self) -> bool:
        return bool(self.upstream.refresh_token)


class GrantStore(Protocol):
    """Where the bridge keeps clients, in-flight sessions, and grants.

    Deliberately narrow. A persistent implementation needs to satisfy exactly this, and
    nothing in the endpoints should reach past it.
    """

    def put_client(self, client: RegisteredClient) -> None: ...
    def get_client(self, client_id: str) -> RegisteredClient | None: ...
    def count_clients(self) -> int: ...
    def purge_unused_clients(self, before: float) -> int: ...

    def put_upstream_client(self, client: UpstreamClient) -> None: ...
    def get_upstream_client(self, server_name: str) -> UpstreamClient | None: ...

    def put_session(self, session: AuthSession) -> None: ...
    def take_session(self, session_id: str) -> AuthSession | None: ...

    def put_grant(self, grant: Grant) -> None: ...
    def take_by_code(self, code: str) -> Grant | None: ...
    def get_by_access_token(self, access_token: str) -> Grant | None: ...
    def get_by_refresh_token(self, refresh_token: str) -> Grant | None: ...
    def newest_grant_for(self, server_name: str) -> Grant | None: ...
    def revoke(self, access_token: str) -> bool: ...


class InMemoryGrantStore:
    """A `GrantStore` held in process memory. Thread-safe.

    Everything is lost on restart. For a single hosted instance that means clients
    re-consent after a deploy — acceptable while the flow is being proven, and the
    reason the persistent implementation is the next piece of work rather than this one.
    """

    def __init__(self) -> None:
        self._clients: dict[str, RegisteredClient] = {}
        self._upstream_clients: dict[str, UpstreamClient] = {}
        self._sessions: dict[str, AuthSession] = {}
        self._by_code: dict[str, Grant] = {}
        self._by_access: dict[str, Grant] = {}
        self._by_refresh: dict[str, Grant] = {}
        self._lock = threading.Lock()

    # ── clients ──────────────────────────────────────────────────────

    def put_client(self, client: RegisteredClient) -> None:
        with self._lock:
            self._clients[client.client_id] = client

    def get_client(self, client_id: str) -> RegisteredClient | None:
        with self._lock:
            return self._clients.get(client_id)

    def count_clients(self) -> int:
        with self._lock:
            return len(self._clients)

    def purge_unused_clients(self, before: float) -> int:
        """Drop old clients that never completed an authorization."""
        with self._lock:
            in_use = {g.client_id for g in self._by_access.values()}
            stale = [
                cid for cid, c in self._clients.items()
                if c.created_at < before and cid not in in_use
            ]
            for cid in stale:
                del self._clients[cid]
            return len(stale)

    # ── upstream registration ────────────────────────────────────────

    def put_upstream_client(self, client: UpstreamClient) -> None:
        with self._lock:
            self._upstream_clients[client.server_name] = client

    def get_upstream_client(self, server_name: str) -> UpstreamClient | None:
        with self._lock:
            return self._upstream_clients.get(server_name)

    # ── sessions ─────────────────────────────────────────────────────

    def put_session(self, session: AuthSession) -> None:
        with self._lock:
            self._purge_sessions()
            self._sessions[session.session_id] = session

    def take_session(self, session_id: str) -> AuthSession | None:
        """Claim an in-flight session. Single use — a replayed callback finds nothing."""
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session is not None and session.is_expired():
            logger.bind(module="minigate.bridge").warning(
                "Discarding an authorization session that expired before consent completed"
            )
            return None
        return session

    def _purge_sessions(self) -> None:
        """Drop sessions nobody completed. Called under the lock."""
        now = time.time()
        stale = [k for k, s in self._sessions.items() if s.is_expired(now)]
        for key in stale:
            del self._sessions[key]

    # ── grants ───────────────────────────────────────────────────────

    def put_grant(self, grant: Grant) -> None:
        with self._lock:
            if grant.code:
                self._by_code[grant.code] = grant
            if grant.access_token:
                self._by_access[grant.access_token] = grant
            if grant.refresh_token:
                self._by_refresh[grant.refresh_token] = grant

    def take_by_code(self, code: str) -> Grant | None:
        """Redeem an authorization code. Single use, and expired codes are refused.

        RFC 6749 §4.1.2 requires a code be usable once; reuse is a signal the code
        leaked, so the entry is removed whether or not it turns out to be valid.
        """
        with self._lock:
            grant = self._by_code.pop(code, None)
        if grant is None:
            return None
        if grant.code_is_expired():
            logger.bind(module="minigate.bridge").warning("Refusing an expired authorization code")
            return None
        return grant

    def get_by_access_token(self, access_token: str) -> Grant | None:
        with self._lock:
            return self._by_access.get(access_token)

    def get_by_refresh_token(self, refresh_token: str) -> Grant | None:
        with self._lock:
            return self._by_refresh.get(refresh_token)

    def newest_grant_for(self, server_name: str) -> Grant | None:
        """The most recent live grant for a server, for reading its manifest.

        A tool manifest is the same whoever asks, so any authorized credential can read
        it. The newest is chosen because it is the least likely to have expired — this
        borrows a credential a user already consented to, rather than asking an operator
        to obtain one by hand.
        """
        with self._lock:
            candidates = [
                g for g in self._by_access.values()
                if g.server_name == server_name and not g.access_is_expired()
            ]
        return max(candidates, key=lambda g: g.created_at, default=None)

    def revoke(self, access_token: str) -> bool:
        """Drop a grant entirely — both halves of it.

        Revoking the access token alone would leave the refresh token able to mint a new
        one, which is not what anyone means by revoke.
        """
        with self._lock:
            grant = self._by_access.pop(access_token, None)
            if grant is None:
                return False
            if grant.refresh_token:
                self._by_refresh.pop(grant.refresh_token, None)
            return True

    # ── introspection, for /healthz and tests ────────────────────────

    @property
    def counts(self) -> dict[str, int]:
        with self._lock:
            return {
                "clients": len(self._clients),
                "sessions": len(self._sessions),
                "grants": len(self._by_access),
            }
