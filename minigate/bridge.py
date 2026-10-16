"""MiniGate as an OAuth authorization server, bridging to an upstream's own.

Passthrough cannot work when the upstream's authorization server serves one resource and
that resource is not ours: RFC 9728 obliges us to advertise our own identifier, the
client propagates it as the RFC 8707 `resource`, and the upstream will not honour a token
minted for a resource it does not own. Proven against Linear on 6 October 2026.

The bridge resolves it by making each leg internally consistent:

    client ──resource=MiniGate──► MiniGate   (we own that resource)
    MiniGate ──resource=upstream──► upstream (it owns that one)

So MiniGate is an authorization server downstream and an ordinary OAuth client upstream.
The two are deliberately separate credentials: the token a client holds is ours, never
the upstream's, and it is exchanged for the upstream's only inside the gateway.

**This reverses ADR-002.** MiniGate now mints and holds tokens, which makes it a
credential store and therefore a target. The storage boundary is `GrantStore` precisely
so that part can be hardened independently; the implementation shipped alongside this
keeps nothing on disk.

The decision layer is untouched. Policy, pinning, DLP, injection scanning and lineage all
run exactly as before — this changes only who authorizes the caller and which credential
travels upstream.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import replace
from typing import Any
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from minigate.bridge_store import (
    _UNUSED_CLIENT_TTL_SECONDS,
    AuthSession,
    Grant,
    GrantStore,
    RegisteredClient,
    UpstreamClient,
    new_token,
)
from minigate.config import GatewayConfig, ServerConfig
from minigate.logging import logger
from minigate.models import Direction, McpEvent
from minigate.oauth_client import (
    ClientRegistration,
    OAuthError,
    PkcePair,
    UpstreamOAuth,
    discover,
)
from minigate.store import EventSink, NullSink

_ACCESS_TOKEN_TTL_SECONDS = 3600

_MAX_REDIRECT_URIS = 5
_MAX_REDIRECT_URI_LENGTH = 2048
_MAX_CLIENTS = 1000
_REGISTRATIONS_PER_HOUR = 20

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

__all__ = ["BridgeError", "OAuthBridge", "bridge_router"]


class BridgeError(Exception):
    """Raised when a bridge step cannot be completed."""


def _redirect_uri_problem(uri: str) -> str | None:
    """Why a redirect URI is unacceptable, or None if it is fine.

    RFC 8252 §7.3: a native client may use `http` only on the loopback interface. Any
    other plaintext target means an authorization code crosses the network in the clear,
    and the code is enough to obtain a token. A fragment is forbidden outright by RFC
    6749 §3.1.2, and a wildcard is how a redirect allowlist becomes an open redirector.
    """
    if len(uri) > _MAX_REDIRECT_URI_LENGTH:
        return "redirect_uri is too long"
    if "*" in uri:
        return "redirect_uri must not contain a wildcard"
    if "#" in uri:
        return "redirect_uri must not contain a fragment"

    try:
        parsed = httpx.URL(uri)
        scheme = parsed.scheme
        host = parsed.host
    except Exception:
        return "redirect_uri is not a valid URL"

    if scheme == "https":
        return None
    if scheme == "http":
        if host in _LOOPBACK_HOSTS:
            return None
        return "http redirect_uri is only permitted on the loopback interface"
    if not scheme:
        return "redirect_uri must be absolute"
    # A private-use scheme (com.example.app:/cb) is how a mobile client registers.
    return None if ":" in uri and "." in scheme else "redirect_uri scheme is not permitted"


class _RateLimiter:
    """A fixed-window counter, keyed by caller.

    Registration is unauthenticated by necessity — a client cannot authenticate before it
    has credentials — so the only thing standing between an open endpoint and unbounded
    growth is a limit. In-process state, which is correct for a single instance and would
    need moving if the gateway is ever replicated.
    """

    def __init__(self, limit: int, window_seconds: float = 3600.0) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        recent = [t for t in self._hits.get(key, []) if now - t < self._window]
        if len(recent) >= self._limit:
            self._hits[key] = recent
            return False
        recent.append(now)
        self._hits[key] = recent
        if len(self._hits) > 10_000:          # bound the keyspace itself
            self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < self._window}
        return True


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    """An RFC 6749 §5.2 error response."""
    return JSONResponse({"error": error, "error_description": description}, status_code=status)


def _verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    """Check a PKCE verifier against the challenge the client registered."""
    if method.upper() == "S256":
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        computed = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return secrets_equal(computed, challenge)
    # `plain` is permitted by RFC 7636 but offers nothing against an attacker who can
    # read the authorization request, which is the threat PKCE exists for.
    return False


def secrets_equal(a: str, b: str) -> bool:
    """Constant-time comparison, so a mismatch leaks no position information."""
    import hmac

    return hmac.compare_digest(a, b)


class OAuthBridge:
    """Holds bridge state and upstream OAuth configuration for one gateway."""

    def __init__(
        self,
        config: GatewayConfig,
        store: GrantStore,
        client: httpx.AsyncClient | None = None,
        sink: EventSink | None = None,
    ) -> None:
        self.config = config
        self.store = store
        # Authorization is a governed action like any other. A gateway that records every
        # tool call but not who was granted the right to make them answers "what
        # happened" and never "who was allowed to".
        self.sink = sink or NullSink()
        self._client = client
        # Upstream authorization-server metadata, discovered once per server and reused.
        self._upstream_meta: dict[str, dict[str, Any]] = {}
        # MiniGate's own registration with each upstream.
        self._upstream_client: dict[str, Any] = {}
        self._registrations = _RateLimiter(_REGISTRATIONS_PER_HOUR)

    # ── identity ─────────────────────────────────────────────────────

    def base_url(self, request: Request | None = None) -> str:
        if self.config.http.public_url:
            return self.config.http.public_url.rstrip("/")
        if request is None:
            msg = "public_url must be configured for the bridge to build its own URLs"
            raise BridgeError(msg)
        return str(request.base_url).rstrip("/")

    def resource_uri(self, request: Request, server_name: str) -> str:
        """What we advertise as this server's resource identifier.

        Always our own URL. That is what RFC 9728 requires, and under the bridge it is
        also now true: we are the resource server the client authenticates to.
        """
        return f"{self.base_url(request)}/mcp/{server_name}"

    def callback_uri(self, request: Request | None = None) -> str:
        return f"{self.base_url(request)}/oauth/callback"

    # ── upstream ─────────────────────────────────────────────────────

    async def upstream_flow(
        self, request: Request | None, server: ServerConfig, name: str
    ) -> UpstreamOAuth:
        """An OAuth client for one upstream, discovering and registering on first use."""
        if name not in self._upstream_meta:
            if not server.url:
                msg = f"Server {name!r} has no URL to discover"
                raise BridgeError(msg)
            try:
                found = await discover(server.url, client=self._client)
            except OAuthError as e:
                raise BridgeError(str(e)) from e
            self._upstream_meta[name] = {
                "metadata": found["authorization_server"],
                "resource": found["resource_metadata"].get("resource") or server.url,
            }

        entry = self._upstream_meta[name]
        flow = UpstreamOAuth(
            entry["metadata"],
            resource=entry["resource"],
            redirect_uri=self.callback_uri(request),
            client=self._client,
        )
        if name not in self._upstream_client:
            # A registration from a previous run is reused: re-registering on every boot
            # mints a new client_id with the vendor each time.
            stored = self.store.get_upstream_client(name)
            if stored is not None:
                self._upstream_client[name] = ClientRegistration(
                    client_id=stored.client_id, client_secret=stored.client_secret
                )
            else:
                try:
                    registration = await flow.register(client_name="MiniGate")
                except OAuthError as e:
                    raise BridgeError(
                        f"Could not register with {name}'s authorization server: {e}"
                    ) from e
                self.store.put_upstream_client(UpstreamClient(
                    server_name=name,
                    client_id=registration.client_id,
                    client_secret=registration.client_secret,
                ))
                self._upstream_client[name] = registration
        return flow

    def upstream_registration(self, name: str) -> Any:
        return self._upstream_client[name]


    def record(
        self,
        *,
        action: str,
        server: str,
        principal: str,
        result: str = "ALLOW",
        reason: str = "",
    ) -> None:
        """Write an authorization event to the audit chain.

        Never raises. Losing an audit record must not break an authorization, for the
        same reason it must not break a tool call — but unlike a tool call there is no
        fail-open subtlety here, because the action has already happened.
        """
        try:
            event = McpEvent(
                client_id=principal,
                session_id="oauth",
                server=server,
                method=f"oauth/{action}",
                direction=Direction.REQUEST,
                policy_result=result,
                reason=reason,
            )
            event.payload_hash = McpEvent.compute_hash(event.payload)
            self.sink.emit(event)
        except Exception as e:
            logger.bind(module="minigate.bridge").warning(
                "Could not record an authorization event: {error}", error=str(e)
            )

    async def refresh_upstream(self, grant: Grant) -> bool:
        """Renew the upstream credential on a grant, in place.

        The vendor's token is short-lived relative to a working session — Linear's lasts
        about a day — so without this a client is silently cut off partway through, with
        the refresh token sitting unused in the grant. Failure is not fatal here: the
        existing token may still have life in it, and the upstream is the authority on
        whether it does.
        """
        server = self.config.servers.get(grant.server_name)
        if server is None or not grant.can_refresh_upstream():
            return False
        try:
            flow = await self.upstream_flow(None, server, grant.server_name)
            tokens = await flow.refresh(
                self.upstream_registration(grant.server_name),
                grant.upstream.refresh_token or "",
            )
            await flow.aclose()
        except (BridgeError, OAuthError) as e:
            logger.bind(module="minigate.bridge").warning(
                "Upstream refresh failed for {server}: {error}",
                server=grant.server_name, error=str(e),
            )
            return False

        # An authorization server may omit the refresh token on renewal, meaning "keep
        # using the one you have". Dropping it there would strand the grant one cycle on.
        if not tokens.refresh_token:
            tokens = replace(tokens, refresh_token=grant.upstream.refresh_token)
        # A renewal usually carries no id_token; the subject established at consent
        # stands until the grant is revoked.
        if not tokens.id_token:
            tokens = replace(tokens, id_token=grant.upstream.id_token)

        grant.upstream = tokens
        grant.upstream_expires_at = (
            time.time() + tokens.expires_in if tokens.expires_in else None
        )
        self.store.put_grant(grant)
        logger.bind(module="minigate.bridge").info(
            "Refreshed the upstream credential for {server} ({token})",
            server=grant.server_name, token=tokens.describe(),
        )
        self.record(
            action="upstream-refresh", server=grant.server_name,
            principal=grant.principal, reason="Renewed the upstream credential",
        )
        return True


def bridge_router(bridge: OAuthBridge) -> APIRouter:
    """The authorization-server endpoints MiniGate exposes to its clients."""
    api = APIRouter()

    # RFC 8414 locates this at the issuer root, which is where our issuer has no path.
    # The suffixed and OIDC variants are served too: clients differ in whether they
    # derive the metadata URL from the issuer or from the resource path, and MCP's later
    # revisions permit OIDC Discovery as an alternative. Answering all of them costs
    # nothing and removes a class of failure that surfaces only as "could not register".
    @api.get("/.well-known/oauth-authorization-server")
    @api.get("/.well-known/oauth-authorization-server/{suffix:path}")
    @api.get("/.well-known/openid-configuration")
    @api.get("/.well-known/openid-configuration/{suffix:path}")
    async def authorization_server_metadata(request: Request) -> Response:
        """RFC 8414 metadata. We are the authorization server now, not the upstream."""
        base = bridge.base_url(request)
        return JSONResponse(
            {
                "issuer": base,
                "authorization_endpoint": f"{base}/oauth/authorize",
                "token_endpoint": f"{base}/oauth/token",
                "registration_endpoint": f"{base}/oauth/register",
                "revocation_endpoint": f"{base}/oauth/revoke",
                "scopes_supported": ["read", "write"],
                "response_types_supported": ["code"],
                "response_modes_supported": ["query"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
                "token_endpoint_auth_methods_supported": ["none"],
                # RFC 9207: the issuer is echoed on the authorization response, which a
                # client may validate before redeeming the code.
                "authorization_response_iss_parameter_supported": False,
            }
        )

    @api.post("/oauth/register")
    async def register(request: Request) -> Response:
        """RFC 7591 dynamic client registration.

        Open registration is what lets a client connect without an onboarding step, and
        it is safe here only because a registered client gets nothing until a human
        completes consent at the upstream. The redirect URIs it registers are the thing
        that matters, and they are matched exactly at /authorize.
        """
        try:
            body = await request.json()
        except Exception:
            return _oauth_error("invalid_request", "Body must be JSON")

        caller = request.client.host if request.client else "unknown"
        if not bridge._registrations.allow(caller):
            return _oauth_error(
                "temporarily_unavailable",
                "Too many registrations from this address; try again later",
                status=429,
            )

        uris = body.get("redirect_uris")
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) for u in uris):
            return _oauth_error("invalid_redirect_uri", "redirect_uris must be a non-empty list")
        if len(uris) > _MAX_REDIRECT_URIS:
            return _oauth_error(
                "invalid_redirect_uri", f"At most {_MAX_REDIRECT_URIS} redirect_uris"
            )
        for uri in uris:
            problem = _redirect_uri_problem(uri)
            if problem:
                return _oauth_error("invalid_redirect_uri", problem)

        # Reclaim registrations that never completed consent before refusing anyone.
        if bridge.store.count_clients() >= _MAX_CLIENTS:
            reclaimed = bridge.store.purge_unused_clients(
                time.time() - _UNUSED_CLIENT_TTL_SECONDS
            )
            logger.bind(module="minigate.bridge").info(
                "Client registry at capacity; reclaimed {count} unused registrations",
                count=reclaimed,
            )
            if bridge.store.count_clients() >= _MAX_CLIENTS:
                return _oauth_error(
                    "temporarily_unavailable",
                    "Client registry is at capacity",
                    status=503,
                )

        client = RegisteredClient(
            client_id=new_token(16),
            redirect_uris=tuple(uris),
            client_name=str(body.get("client_name") or "unknown"),
        )
        bridge.store.put_client(client)
        logger.bind(module="minigate.bridge").info(
            "Registered client {name} ({client_id})",
            name=client.client_name,
            client_id=client.client_id,
        )
        return JSONResponse(
            {
                "client_id": client.client_id,
                "client_id_issued_at": int(client.created_at),
                "redirect_uris": list(client.redirect_uris),
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
            },
            status_code=201,
        )

    @api.get("/oauth/authorize")
    async def authorize(request: Request) -> Response:
        """Begin an authorization, and hand the user to the upstream for consent.

        Two PKCE pairs are in play and must not be confused: the client's challenge,
        which we verify at our token endpoint, and ours, which the upstream verifies at
        its own. Only ours is generated here.
        """
        q = request.query_params
        client_id = q.get("client_id", "")
        redirect_uri = q.get("redirect_uri", "")

        client = bridge.store.get_client(client_id)
        if client is None:
            return _oauth_error("invalid_client", "Unknown client_id")
        if not client.allows(redirect_uri):
            # Never redirect to an unregistered URI, even to report the error — that is
            # the open-redirect this check exists to prevent.
            return _oauth_error("invalid_request", "redirect_uri was not registered")

        server_name = _server_from_resource(bridge, request, q.get("resource"))
        if server_name is None:
            return _oauth_error("invalid_target", "resource does not name a governed server")

        server = bridge.config.servers.get(server_name)
        if server is None or not server.is_remote:
            return _oauth_error("invalid_target", f"No remote server named {server_name!r}")

        mode = server.auth_mode or bridge.config.http.auth.mode
        if mode != "bridge":
            # Refuse here with a clear reason rather than failing later at registration:
            # an upstream that cannot be bridged usually cannot register us as a client,
            # and "no registration_endpoint" is an opaque way to learn that.
            return _oauth_error(
                "invalid_target",
                f"Server {server_name!r} is not configured for bridge mode; "
                f"authorize against its own authorization server instead",
            )

        try:
            flow = await bridge.upstream_flow(request, server, server_name)
        except BridgeError as e:
            return _oauth_error("server_error", str(e), status=502)

        pkce = PkcePair.generate()
        session = AuthSession(
            session_id=new_token(24),
            client_id=client_id,
            server_name=server_name,
            client_redirect_uri=redirect_uri,
            client_state=q.get("state"),
            client_code_challenge=q.get("code_challenge"),
            client_code_challenge_method=q.get("code_challenge_method", "S256"),
            upstream_verifier=pkce.verifier,
        )
        bridge.store.put_session(session)

        upstream_url = flow.authorize_url(
            bridge.upstream_registration(server_name), pkce, state=session.session_id
        )
        await flow.aclose()
        return RedirectResponse(upstream_url, status_code=302)

    @api.get("/oauth/callback")
    async def callback(request: Request) -> Response:
        """The upstream returns the user here. Exchange its code, then issue ours."""
        q = request.query_params
        session = bridge.store.take_session(q.get("state", ""))
        if session is None:
            return _oauth_error("invalid_request", "Unknown or expired authorization session")

        if "code" not in q:
            detail = q.get("error_description") or q.get("error") or "no code returned"
            return _redirect_error(session, "access_denied", detail)

        server = bridge.config.servers.get(session.server_name)
        if server is None:
            return _oauth_error("server_error", "Server disappeared mid-flow", status=500)

        try:
            flow = await bridge.upstream_flow(request, server, session.server_name)
            tokens = await flow.exchange(
                bridge.upstream_registration(session.server_name),
                q["code"],
                PkcePair.from_verifier(session.upstream_verifier),
            )
            await flow.aclose()
        except (BridgeError, OAuthError) as e:
            logger.bind(module="minigate.bridge").warning(
                "Upstream exchange failed for {server}: {error}",
                server=session.server_name,
                error=str(e),
            )
            return _redirect_error(session, "server_error", "upstream token exchange failed")

        identity = tokens.identity()
        grant = Grant(
            grant_id=new_token(16),
            client_id=session.client_id,
            server_name=session.server_name,
            upstream=tokens,
            subject=identity.get("sub"),
            subject_email=identity.get("email"),
            code=new_token(24),
            code_challenge=session.client_code_challenge,
            code_challenge_method=session.client_code_challenge_method,
            redirect_uri=session.client_redirect_uri,
        )
        bridge.store.put_grant(grant)

        logger.bind(module="minigate.bridge").info(
            "Bridged an authorization for {server} as {principal} ({token})",
            server=session.server_name,
            principal=grant.principal,
            token=tokens.describe(),
        )

        bridge.record(
            action="authorize", server=session.server_name, principal=grant.principal,
            reason=f"Authorization granted to client {session.client_id}",
        )

        params = {"code": grant.code}
        if session.client_state:
            params["state"] = session.client_state
        return RedirectResponse(f"{session.client_redirect_uri}?{urlencode(params)}", status_code=302)

    @api.post("/oauth/token")
    async def token(
        request: Request,
        grant_type: str = Form(default=""),
        code: str = Form(default=""),
        code_verifier: str = Form(default=""),
        client_id: str = Form(default=""),
        redirect_uri: str = Form(default=""),
        refresh_token: str = Form(default=""),
    ) -> Response:
        """Issue our access token, from an authorization code or from our refresh token."""
        if grant_type == "refresh_token":
            return _issue_from_refresh(bridge, refresh_token, client_id)
        if grant_type != "authorization_code":
            return _oauth_error("unsupported_grant_type", f"{grant_type!r} is not supported")

        grant = bridge.store.take_by_code(code)
        if grant is None:
            return _oauth_error("invalid_grant", "Unknown, expired, or already-used code")
        if client_id and grant.client_id != client_id:
            return _oauth_error("invalid_grant", "Code was issued to a different client")
        if redirect_uri and grant.redirect_uri != redirect_uri:
            return _oauth_error("invalid_grant", "redirect_uri does not match the authorization")

        if grant.code_challenge:
            if not code_verifier:
                return _oauth_error("invalid_request", "code_verifier is required")
            if not _verify_pkce(code_verifier, grant.code_challenge, grant.code_challenge_method):
                return _oauth_error("invalid_grant", "PKCE verification failed")

        grant.code = None
        grant.upstream_expires_at = (
            grant.created_at + grant.upstream.expires_in if grant.upstream.expires_in else None
        )
        return _issue(bridge, grant)

    @api.post("/oauth/revoke")
    async def revoke(token: str = Form(default="")) -> Response:
        """RFC 7009. Always 200, so a caller cannot probe which tokens exist."""
        if token:
            grant = bridge.store.get_by_access_token(token)
            if grant is not None:
                bridge.record(
                    action="revoke", server=grant.server_name, principal=grant.principal,
                    result="BLOCK", reason="Access revoked at the client's request",
                )
            bridge.store.revoke(token)
        return Response(status_code=200)

    return api


def _issue(bridge: OAuthBridge, grant: Grant) -> Response:
    """Mint our access and refresh tokens for a grant, and persist them.

    Both are rotated on every issue. A refresh token that survives its own use is a
    long-lived bearer credential, which is the thing rotation exists to avoid.
    """
    first_issue = grant.access_token is None
    grant.access_token = new_token(32)
    grant.refresh_token = new_token(32)
    grant.access_expires_at = time.time() + _ACCESS_TOKEN_TTL_SECONDS
    bridge.store.put_grant(grant)

    bridge.record(
        action="token" if first_issue else "renew",
        server=grant.server_name,
        principal=grant.principal,
        reason="Access token issued" if first_issue else "Access token renewed",
    )

    return JSONResponse(
        {
            "access_token": grant.access_token,
            "token_type": "Bearer",
            "expires_in": _ACCESS_TOKEN_TTL_SECONDS,
            "refresh_token": grant.refresh_token,
            "scope": grant.upstream.scope or "",
        },
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def _issue_from_refresh(bridge: OAuthBridge, refresh_token: str, client_id: str) -> Response:
    """Renew a client's access token from the refresh token we issued it."""
    if not refresh_token:
        return _oauth_error("invalid_request", "refresh_token is required")

    grant = bridge.store.get_by_refresh_token(refresh_token)
    if grant is None:
        return _oauth_error("invalid_grant", "Unknown or already-used refresh token")
    if client_id and grant.client_id != client_id:
        return _oauth_error("invalid_grant", "Refresh token was issued to a different client")

    # Drop the old pair before minting the new one, so the presented token cannot be
    # used twice even if two requests arrive together.
    if grant.access_token:
        bridge.store.revoke(grant.access_token)
    return _issue(bridge, grant)


def _redirect_error(session: AuthSession, error: str, description: str) -> Response:
    """Report a failure to the client at its registered redirect URI."""
    params = {"error": error, "error_description": description}
    if session.client_state:
        params["state"] = session.client_state
    return RedirectResponse(f"{session.client_redirect_uri}?{urlencode(params)}", status_code=302)


def _server_from_resource(bridge: OAuthBridge, request: Request, resource: str | None) -> str | None:
    """Which governed server a `resource` indicator names.

    Clients send the resource they are authorizing for. With exactly one governed server
    the parameter is redundant and is allowed to be absent; with several it is the only
    thing distinguishing them, so it is required.
    """
    names = [n for n, s in bridge.config.servers.items() if s.is_remote]
    if resource:
        wanted = resource.rstrip("/")
        for name in names:
            if bridge.resource_uri(request, name).rstrip("/") == wanted:
                return name
        # A client may send the bare gateway URL rather than the per-server path.
        if wanted == bridge.base_url(request) and len(names) == 1:
            return names[0]
        return None
    return names[0] if len(names) == 1 else None


async def swap_authorization(
    bridge: OAuthBridge, presented: str | None, server_name: str | None = None
) -> tuple[str | None, Grant | None]:
    """Trade a client's MiniGate token for the upstream credential it maps to.

    Returns `(authorization_header, grant)`. A `None` header means the token was not
    recognised or has expired and the request must be challenged — the upstream is never
    contacted on behalf of a credential we do not hold.

    The upstream half is renewed here when it is at or near expiry, which is the only
    point in the system that reliably runs before every upstream call.
    """
    if not presented or not presented.lower().startswith("bearer "):
        return None, None
    grant = bridge.store.get_by_access_token(presented[7:].strip())
    if grant is None:
        return None, None
    if grant.access_is_expired():
        bridge.store.revoke(grant.access_token or "")
        return None, None

    # A grant authorizes one upstream, not the gateway. Without this check a token
    # issued for one server is accepted at another and that server's credential is
    # forwarded to an endpoint it was never issued for — the upstream would refuse it,
    # but the refusal belongs here, where the authorization boundary actually is.
    if server_name is not None and grant.server_name != server_name:
        logger.bind(module="minigate.bridge").warning(
            "Refusing a token issued for {held} presented against {wanted}",
            held=grant.server_name, wanted=server_name,
        )
        return None, None

    if grant.upstream_needs_refresh() and not await bridge.refresh_upstream(grant):
        # The refresh failed but the existing token may still be live; the upstream is
        # the authority on that, so the call proceeds and is refused there if it is not.
        logger.bind(module="minigate.bridge").warning(
            "Proceeding with an unrefreshed upstream credential for {server}",
            server=grant.server_name,
        )
    return grant.upstream.authorization_header, grant
