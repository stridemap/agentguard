"""Remote gateway mode — MiniGate as an MCP server over Streamable HTTP.

Clients connect to MiniGate at `POST /mcp/{server}` instead of to the vendor's endpoint,
and MiniGate proxies to the real one. This is what covers claude.ai on the web and any
centrally administered deployment, where per-endpoint stdio configuration is not viable.

The decision layer is unchanged. `GatewayCore` has no I/O of its own, so every control
built for stdio — policy, registry pinning, DLP, injection scanning, lineage, and the
reverse-direction sampling and elicitation gates — applies here with no new logic.

**OAuth is passthrough, not proxied.** MiniGate advertises the upstream's own
authorization server in its protected-resource metadata; the client obtains a token from
that server and MiniGate relays the Authorization header verbatim. No token is minted,
stored, or refreshed here, which keeps the gateway out of the credential-custody business
for the same reason ADR-001 keeps it out of TLS interception.

The trade-off is real and worth stating: an upstream that strictly validates token
audience against its own canonical URI (RFC 8707) may reject a token the client bound to
MiniGate's URI. Set `public_url` to the upstream's resource identifier when that happens,
or run the upstream in a mode that accepts the gateway as an audience.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import time
from collections.abc import AsyncIterator
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from minigate.bridge import OAuthBridge, bridge_router, swap_authorization
from minigate.config import GatewayConfig, ServerConfig
from minigate.core import GatewayCore, current_principal
from minigate.logging import logger
from minigate.registry import RegistryMode
from minigate.router import MessageRouter, is_request, is_response
from minigate.store import NullSink

_SSE_MEDIA_TYPE = "text/event-stream"
_JSON_MEDIA_TYPE = "application/json"
_SESSION_HEADER = "mcp-session-id"

# Hop-by-hop and length-bearing headers must not be relayed: the body is re-encoded after
# governance, so a forwarded Content-Length would describe the wrong payload.
_SKIP_REQUEST_HEADERS = frozenset(
    {"host", "content-length", "connection", "transfer-encoding", "keep-alive"}
)
_SKIP_RESPONSE_HEADERS = frozenset(
    {"content-length", "content-encoding", "connection", "transfer-encoding", "keep-alive"}
)


class UnknownServerError(Exception):
    """Raised when a request names a server that is not configured."""


class GatewayApp:
    """Holds one GatewayCore per configured server, plus the upstream HTTP client.

    Cores are built once at startup rather than per request, so registry state and the
    tools/list verdict cache survive across a session the way they do on stdio.
    """

    def __init__(
        self,
        config: GatewayConfig,
        cores: dict[str, GatewayCore],
        client: httpx.AsyncClient | None = None,
        bridge: OAuthBridge | None = None,
    ) -> None:
        self.config = config
        self.cores = cores
        # Present only in bridge mode, where MiniGate issues its own tokens and holds
        # the upstream credentials they map to.
        self.bridge = bridge
        self.client = client or httpx.AsyncClient(
            timeout=config.http.upstream_timeout_seconds, follow_redirects=True
        )
        # One router per MCP session, so correlation survives across the several POSTs
        # that make up a conversation. Keyed by Mcp-Session-Id.
        self._routers: dict[str, MessageRouter] = {}
        # Last manifest-warm attempt per upstream URL, so a tool the server genuinely
        # does not advertise cannot turn every retry into a full manifest fetch.
        self.warmed: dict[str, float] = {}

    def server_config(self, name: str) -> ServerConfig:
        server = self.config.servers.get(name)
        if server is None or not server.is_remote:
            msg = f"No remote server named {name!r} is configured"
            raise UnknownServerError(msg)
        return server

    def uses_bridge(self, name: str) -> bool:
        """Whether this server authenticates callers through MiniGate's own AS.

        Per-server: an upstream that does not support dynamic client registration cannot
        be bridged, and a gateway fronting several upstreams will generally need both.
        """
        if self.bridge is None:
            return False
        server = self.config.servers.get(name)
        mode = (server.auth_mode if server and server.auth_mode else self.config.http.auth.mode)
        return mode == "bridge"

    def core(self, name: str) -> GatewayCore:
        core = self.cores.get(name)
        if core is None:
            msg = f"No gateway configured for server {name!r}"
            raise UnknownServerError(msg)
        return core

    def router(self, session_id: str | None) -> MessageRouter:
        """The correlation state for a session, created on first sight.

        Sessionless callers each get their own router rather than sharing one. JSON-RPC
        ids are unique only per client, so two clients that both open with id 1 — the
        common case — would otherwise collide in a single correlation map: the first
        response to arrive claims the entry, and the second finds nothing and is relayed
        with no request context. A `tools/call` result in that state is forwarded
        unscanned, unredacted and unrecorded, because governing a result requires knowing
        which call it answers.

        Nothing is lost by not sharing. Cross-POST correlation exists for server-initiated
        requests, whose replies arrive in a later POST — and a client with no session id
        has no defined way to be correlated across POSTs in the first place. A stateless
        upstream, which mints no session id and makes no server-initiated requests, is
        exactly this case.
        """
        if session_id is None:
            return MessageRouter()
        if session_id not in self._routers:
            self._routers[session_id] = MessageRouter()
        return self._routers[session_id]

    def forget(self, session_id: str | None) -> None:
        if session_id is not None:
            self._routers.pop(session_id, None)

    def resource_uri(self, request: Request, name: str) -> str:
        """The OAuth resource identifier for one governed server.

        A per-server `resource_identifier` wins outright. Passthrough means the token is
        minted by the upstream's authorization server, and one honouring RFC 8707 will not
        issue a token for a resource it does not own — so advertising MiniGate's own URI
        gets the client a token the upstream then rejects. Setting the upstream's
        identifier here trades strict RFC 9728 correctness for a flow that completes.

        Otherwise the configured `public_url`: behind a TLS terminator the request host is
        the proxy's, not the one the client dialled, and an identifier the client does not
        recognise fails discovery.
        """
        server = self.config.servers.get(name)
        if server is not None and server.resource_identifier:
            return server.resource_identifier
        base = (self.config.http.public_url or str(request.base_url)).rstrip("/")
        return f"{base}/mcp/{name}"

    async def aclose(self) -> None:
        await self.client.aclose()


# ── Governance of one direction's messages ───────────────────────────


def _govern_outbound(
    core: GatewayCore, router: MessageRouter, messages: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Apply client-to-server governance.

    Synchronous and CPU-bound: DLP and injection scanning dominate it. Callers on the
    event loop must dispatch this to a worker thread — see `_govern_outbound_async`.

    Returns:
        (to_forward, answered_locally) — blocked calls never reach the upstream, and
        their synthetic responses go straight back to the client.
    """
    forward: list[dict[str, Any]] = []
    answered: list[dict[str, Any]] = []

    for msg in messages:
        if is_response(msg):
            pending = router.take_server_request(msg["id"])
            if pending is not None:
                forward.append(core.on_client_response(msg, pending.method))
                continue

        if is_request(msg):
            router.note_client_request(msg)

        short_circuit = core.on_client_message(msg)
        if short_circuit is not None:
            router.drop_client_request(msg.get("id"))
            answered.append(short_circuit)
            continue
        forward.append(msg)

    return forward, answered


_WARM_COOLDOWN_SECONDS = 30.0
"""How long to wait before re-attempting a manifest warm for the same server.

Without it, a call naming a tool the upstream genuinely does not advertise would fetch
the whole manifest on every retry.
"""


def _messages_needing_verdicts(core: GatewayCore, messages: list[dict[str, Any]]) -> bool:
    """Whether any `tools/call` here would be judged against a verdict we do not hold."""
    if core.registry is None or core.registry.mode != RegistryMode.ENFORCE:
        return False
    return any(
        msg.get("method") == "tools/call"
        and not core.has_verdict((msg.get("params") or {}).get("name", ""))
        for msg in messages
    )


def _tools_from_payload(raw: bytes, content_type: str) -> list[dict[str, Any]]:
    """Pull a tool list out of a `tools/list` response, JSON or SSE."""
    candidates: list[Any] = []
    if _SSE_MEDIA_TYPE in content_type:
        for block in raw.decode("utf-8", "replace").split("\n\n"):
            data = "\n".join(
                line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")
            )
            if data:
                with contextlib.suppress(json.JSONDecodeError):
                    candidates.append(json.loads(data))
    else:
        with contextlib.suppress(json.JSONDecodeError):
            candidates.append(json.loads(raw))

    for item in candidates:
        for msg in item if isinstance(item, list) else [item]:
            if not isinstance(msg, dict):
                continue
            tools = (msg.get("result") or {}).get("tools")
            if isinstance(tools, list):
                return tools
    return []


async def _warm_verdicts(
    app: GatewayApp,
    core: GatewayCore,
    server: ServerConfig,
    messages: list[dict[str, Any]],
    headers: dict[str, str],
) -> None:
    """Fetch the upstream manifest when a call arrives on a replica that has not seen one.

    The verdict cache lives in the process. Behind a load balancer that is a correctness
    problem: a client lists tools against replica A and calls against replica B, and B
    refuses a perfectly good call as UNVERIFIED. Rather than require session affinity —
    which the 2026 revision removes the basis for — the replica asks the upstream itself.

    The caller's own headers are reused, so no credential is minted or stored here and the
    request carries exactly the authority the client already had. Failure is silent and
    leaves the cache cold, which falls back to the existing refusal rather than admitting
    an unverified call.
    """
    if not _messages_needing_verdicts(core, messages):
        return

    now = time.monotonic()
    last = app.warmed.get(server.url, 0.0)
    if now - last < _WARM_COOLDOWN_SECONDS:
        return
    app.warmed[server.url] = now

    probe = {"jsonrpc": "2.0", "id": "minigate-warm", "method": "tools/list"}
    try:
        response = await app.client.post(server.url, json=probe, headers=headers)
    except httpx.HTTPError as e:
        logger.bind(module="minigate.http").warning(
            "Could not warm registry verdicts for {server}: {error}",
            server=core.server,
            error=str(e),
        )
        return

    if response.status_code >= 400:
        logger.bind(module="minigate.http").warning(
            "Registry warm for {server} refused upstream: {status}",
            server=core.server,
            status=response.status_code,
        )
        return

    tools = _tools_from_payload(response.content, response.headers.get("content-type", ""))
    if tools:
        core.prime_verdicts(tools)
        logger.bind(module="minigate.http").info(
            "Warmed {count} verdicts for {server} on a cold replica",
            count=len(tools),
            server=core.server,
        )


async def _govern_outbound_async(
    core: GatewayCore, router: MessageRouter, messages: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Govern a client-to-server batch without blocking the event loop.

    Scanning a single tool result costs tens of milliseconds, almost all of it inside
    Presidio and the injection patterns. Run inline on the loop, concurrent requests
    serialise behind each other and the gateway's throughput collapses to one scan at a
    time no matter how many clients are connected — measured at eight concurrent calls
    taking eight times one call.

    A thread is the right tool rather than a process: the work is in C extensions that
    release the GIL, so threads genuinely overlap. `GatewayCore` is already driven from
    threads by the stdio proxy, so this adds no new concurrency assumption.
    """
    return await asyncio.to_thread(_govern_outbound, core, router, messages)


async def _govern_inbound(
    app: GatewayApp,
    core: GatewayCore,
    router: MessageRouter,
    msg: dict[str, Any],
    upstream_url: str,
    headers: dict[str, str],
) -> dict[str, Any] | None:
    """Apply server-to-client governance to one upstream message.

    Returns the message to deliver, or None when it must not reach the client — a
    rejected server-initiated request, whose error is POSTed back upstream instead,
    exactly as a client would answer it.
    """
    if is_request(msg):
        rejection = await asyncio.to_thread(core.on_server_request, msg)
        if rejection is None:
            router.note_server_request(msg)
            return msg
        try:
            await app.client.post(upstream_url, json=rejection, headers=headers)
        except httpx.HTTPError as e:
            logger.bind(module="minigate.http").warning(
                "Could not return rejection upstream: {error}", error=str(e)
            )
        return None

    pending = router.take_client_request(msg["id"]) if is_response(msg) else None
    return await asyncio.to_thread(
        core.on_server_message,
        msg,
        pending.method if pending else None,
        pending.tool if pending else None,
        pending.uri if pending else None,
        pending.prompt if pending else None,
    )


# ── SSE ──────────────────────────────────────────────────────────────


async def _iter_sse_messages(lines: AsyncIterator[str]) -> AsyncIterator[tuple[str, dict | None]]:
    """Yield (raw_event_block, parsed_json_or_None) for each SSE event.

    The raw block is kept so anything that is not a JSON-RPC payload — comments,
    retry directives, id lines — is relayed byte-for-byte rather than reconstructed.
    """
    block: list[str] = []
    async for line in lines:
        if line.strip():
            block.append(line)
            continue
        if not block:
            continue
        raw = "\n".join(block)
        data = "\n".join(ln[5:].lstrip() for ln in block if ln.startswith("data:"))
        parsed = None
        if data:
            try:
                loaded = json.loads(data)
                parsed = loaded if isinstance(loaded, dict) else None
            except json.JSONDecodeError:
                parsed = None
        yield raw, parsed
        block = []
    if block:
        yield "\n".join(block), None


def _sse_event(msg: dict[str, Any]) -> str:
    return f"data: {json.dumps(msg, separators=(',', ':'))}\n\n"


# ── App factory ──────────────────────────────────────────────────────


def create_app(app_state: GatewayApp) -> FastAPI:
    """Build the FastAPI application for a configured gateway."""
    api = FastAPI(title="MiniGate", docs_url=None, redoc_url=None)

    @api.middleware("http")
    async def log_requests(request: Request, call_next):
        """One line per request, so a failing client is diagnosable from the server side.

        The audit chain records governed tool calls; it says nothing about a request that
        never got that far. A client failing during OAuth discovery — or refusing the GET
        stream — leaves no trace in it at all, which made a real connector failure
        undiagnosable from here.

        Deliberately no bodies and no Authorization header: this log is operational, the
        audit chain is the evidence, and a bearer token in a platform log is a credential
        leak. Only whether one was present.
        """
        started = time.perf_counter()
        response = await call_next(request)
        logger.bind(module="minigate.http").info(
            "{method} {path} -> {status} ({elapsed:.0f}ms) auth={auth} ua={ua}",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            elapsed=(time.perf_counter() - started) * 1000,
            auth="yes" if request.headers.get("authorization") else "no",
            ua=(request.headers.get("user-agent") or "-")[:60],
        )
        return response

    if app_state.bridge is not None:
        api.include_router(bridge_router(app_state.bridge))

    @api.get("/")
    async def root(request: Request) -> Response:
        """What a human sees when they click the URL.

        The gateway is an API and every real route is either `/mcp/{server}` or an OAuth
        discovery path, so `/` would otherwise be a bare 404 — indistinguishable from a
        dead deployment for anyone who was sent the link. This says what the service is
        and where to look, and deliberately says nothing a caller could not already learn
        from the unauthenticated discovery endpoints.
        """
        return JSONResponse(
            {
                "service": "MiniGate",
                "description": (
                    "Security gateway for the Model Context Protocol. Clients connect "
                    "here instead of to the vendor endpoint; every tool call is evaluated "
                    "against policy and recorded before it is forwarded."
                ),
                "mcp_endpoints": [
                    f"{app_state.resource_uri(request, name)}" for name in sorted(app_state.cores)
                ],
                "health": "/healthz",
                "authorization": (
                    "Bearer token issued by the upstream vendor. MiniGate relays it "
                    "verbatim and mints nothing of its own."
                ),
                "vendor": "https://stridemap.ai",
            }
        )

    @api.get("/healthz")
    async def healthz() -> Response:
        """Liveness, plus the two ways a healthy-looking process is not doing its job.

        `create_sink` degrades to NullSink when the audit store cannot be opened, and
        `Guardrails` disables DLP after a scanner error. Both are deliberate fail-open
        behaviour and both are invisible from outside — a gateway that has quietly stopped
        recording or stopped redacting answers every request exactly as before. Report
        them here so a platform health check can see it.
        """
        degraded = [
            f"{name}: audit sink is NullSink — events are not being recorded"
            for name, core in sorted(app_state.cores.items())
            if isinstance(core.sink, NullSink)
        ] + [
            f"{name}: DLP disabled after a scanner error — responses are not redacted"
            for name, core in sorted(app_state.cores.items())
            if getattr(core.guardrails, "_dlp_failed", False)
        ]
        body: dict[str, Any] = {
            "status": "degraded" if degraded else "ok",
            "servers": sorted(app_state.cores),
            "auth_mode": app_state.config.http.auth.mode,
        }
        if degraded:
            body["degraded"] = degraded
        # 200 either way: this is liveness, and a degraded gateway still governs traffic.
        # Restarting it would not fix an unreachable database, and would drop live sessions.
        return JSONResponse(body)

    @api.get("/.well-known/oauth-protected-resource/mcp/{name}")
    async def protected_resource_metadata(name: str, request: Request) -> Response:
        """RFC 9728 metadata: which authorization server issues tokens for this resource."""
        try:
            server = app_state.server_config(name)
        except UnknownServerError as e:
            return JSONResponse({"error": str(e)}, status_code=404)

        if app_state.uses_bridge(name):
            # We issue the client's token now, so we are its authorization server. This
            # is also what makes the advertised resource honest: the client really does
            # authenticate to us.
            base = app_state.bridge.base_url(request)
            return JSONResponse(
                {
                    "resource": app_state.bridge.resource_uri(request, name),
                    "authorization_servers": [base],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": server.scopes or ["read", "write"],
                }
            )

        return JSONResponse(
            {
                "resource": app_state.resource_uri(request, name),
                "authorization_servers": server.authorization_servers,
                "bearer_methods_supported": ["header"],
                "scopes_supported": server.scopes,
            }
        )

    @api.delete("/mcp/{name}")
    async def terminate(name: str, request: Request) -> Response:
        """Relay session termination, and drop the correlation state with it."""
        try:
            server = app_state.server_config(name)
        except UnknownServerError as e:
            return JSONResponse({"error": str(e)}, status_code=404)

        session_id = request.headers.get(_SESSION_HEADER)
        app_state.forget(session_id)
        try:
            upstream = await app_state.client.delete(
                server.url, headers=_relay_request_headers(request)
            )
        except httpx.HTTPError as e:
            return JSONResponse({"error": f"upstream unreachable: {e}"}, status_code=502)
        return Response(status_code=upstream.status_code)

    @api.get("/mcp/{name}")
    async def server_stream(name: str) -> Response:
        """The optional server-to-client stream is not implemented yet.

        405 rather than a silent 404: the distinction between "no such endpoint" and
        "this endpoint exists but the gateway will not open it" matters to a client
        deciding whether to fall back to POST-only operation.
        """
        return JSONResponse(
            {
                "error": "MiniGate does not yet proxy the GET server-to-client stream. "
                "Server-initiated requests arriving on a POST response stream are governed."
            },
            status_code=405,
        )

    @api.post("/mcp/{name}")
    async def proxy(name: str, request: Request) -> Response:
        try:
            server = app_state.server_config(name)
            core = app_state.core(name)
        except UnknownServerError as e:
            return JSONResponse({"error": str(e)}, status_code=404)

        auth = app_state.config.http.auth
        if auth.require and auth.mode != "none" and not request.headers.get("authorization"):
            metadata = (
                f"{(app_state.config.http.public_url or str(request.base_url)).rstrip('/')}"
                f"/.well-known/oauth-protected-resource/mcp/{name}"
            )
            return JSONResponse(
                {"error": "authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata}"'},
            )

        try:
            body = json.loads(await request.body() or b"null")
        except json.JSONDecodeError:
            return JSONResponse({"error": "request body is not valid JSON"}, status_code=400)

        messages = [m for m in (body if isinstance(body, list) else [body]) if isinstance(m, dict)]
        if not messages:
            return JSONResponse({"error": "no JSON-RPC message in request"}, status_code=400)

        session_id = request.headers.get(_SESSION_HEADER)
        router = app_state.router(session_id)

        headers = _relay_request_headers(request)

        # In bridge mode the caller holds a token MiniGate issued, which is meaningless
        # upstream. Trade it for the credential it maps to before anything — including
        # the verdict warm — talks to the upstream. An unrecognised token is challenged
        # here, so the upstream is never contacted on its behalf.
        if app_state.uses_bridge(name):
            upstream_auth, grant = await swap_authorization(
                app_state.bridge, request.headers.get("authorization"), name
            )
            if upstream_auth is None:
                metadata = (
                    f"{app_state.bridge.base_url(request)}"
                    f"/.well-known/oauth-protected-resource/mcp/{name}"
                )
                return JSONResponse(
                    {"error": "invalid_token"},
                    status_code=401,
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer resource_metadata="{metadata}", error="invalid_token"'
                        )
                    },
                )
            headers["authorization"] = upstream_auth
            # Every event emitted while handling this request is attributed to whoever
            # the presented token belongs to, rather than to one configured client id.
            if grant is not None:
                current_principal.set(grant.principal)

        # Before judging anything, make sure this replica actually holds the verdicts it
        # is about to judge against. See _warm_verdicts.
        await _warm_verdicts(app_state, core, server, messages, headers)

        forward, answered = await _govern_outbound_async(core, router, messages)

        if not forward:
            # Everything was blocked here, so nothing needs to reach the upstream at all.
            return JSONResponse(answered[0] if len(answered) == 1 else answered)

        payload = forward[0] if len(forward) == 1 else forward

        try:
            upstream = await app_state.client.send(
                app_state.client.build_request(
                    "POST", server.url, json=payload, headers=headers
                ),
                stream=True,
            )
        except httpx.HTTPError as e:
            logger.bind(module="minigate.http").warning(
                "Upstream {url} unreachable: {error}", url=server.url, error=str(e)
            )
            return JSONResponse({"error": f"upstream unreachable: {e}"}, status_code=502)

        content_type = upstream.headers.get("content-type", "")
        out_headers = _relay_response_headers(upstream)

        if upstream.status_code in (401, 403):

            # Why the upstream refused, in its own words. Without this, an authorization
            # failure looks identical from here whatever caused it — a wrong audience, an
            # expired token, a missing scope — and the only place that distinction exists
            # is in the upstream's response. The bearer token is never logged; this is the
            # upstream's error, not the client's credential.
            # A fingerprint, not the token: eight hex characters of its SHA-256. Enough
            # to tell one credential from another across requests — "is this still the
            # token that failed an hour ago, or a new one?" — while revealing nothing
            # about the credential itself.
            presented = (request.headers.get("authorization") or "")[7:]
            fingerprint = (
                hashlib.sha256(presented.encode()).hexdigest()[:8] if presented else "none"
            )
            logger.bind(module="minigate.http").warning(
                "Upstream refused: {status} token={fp} len={n} www-authenticate={challenge!r}",
                status=upstream.status_code,
                fp=fingerprint,
                n=len(presented),
                challenge=upstream.headers.get("www-authenticate", "")[:120],
            )

        if _SSE_MEDIA_TYPE in content_type:
            return StreamingResponse(
                _stream_governed(app_state, core, router, upstream, server, headers, answered),
                status_code=upstream.status_code,
                media_type=_SSE_MEDIA_TYPE,
                headers=out_headers,
            )

        raw = await upstream.aread()
        await upstream.aclose()

        if not raw:
            return Response(status_code=upstream.status_code, headers=out_headers)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return Response(
                content=raw,
                status_code=upstream.status_code,
                headers=out_headers,
                media_type=content_type or _JSON_MEDIA_TYPE,
            )

        items = parsed if isinstance(parsed, list) else [parsed]
        governed: list[dict[str, Any]] = list(answered)
        for msg in items:
            if not isinstance(msg, dict):
                continue
            result = await _govern_inbound(
                app_state, core, router, msg, server.url, headers
            )
            if result is not None:
                governed.append(result)

        return JSONResponse(
            governed[0] if len(governed) == 1 else governed,
            status_code=upstream.status_code,
            headers=out_headers,
        )

    return api


async def _stream_governed(
    app_state: GatewayApp,
    core: GatewayCore,
    router: MessageRouter,
    upstream: httpx.Response,
    server: ServerConfig,
    headers: dict[str, str],
    answered: list[dict[str, Any]],
) -> AsyncIterator[str]:
    """Relay an upstream SSE stream, governing each JSON-RPC payload as it passes.

    Governance is applied per event rather than after buffering the stream, so the first
    token still reaches the client promptly — a gateway that waited for the whole stream
    would be indistinguishable from a slow model.
    """
    try:
        for msg in answered:
            yield _sse_event(msg)
        async for raw, parsed in _iter_sse_messages(upstream.aiter_lines()):
            if parsed is None:
                yield raw + "\n\n"
                continue
            governed = await _govern_inbound(
                app_state, core, router, parsed, server.url, headers
            )
            if governed is not None:
                yield _sse_event(governed)
    except httpx.HTTPError as e:
        logger.bind(module="minigate.http").warning("Upstream stream failed: {error}", error=str(e))
    finally:
        await upstream.aclose()


def _relay_request_headers(request: Request) -> dict[str, str]:
    """Headers to carry upstream, including the client's bearer token verbatim."""
    return {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in _SKIP_REQUEST_HEADERS
    }


def _relay_response_headers(upstream: httpx.Response) -> dict[str, str]:
    """Headers to carry back, notably Mcp-Session-Id so the session survives the hop."""
    return {
        key: value
        for key, value in upstream.headers.items()
        if key.lower() not in _SKIP_RESPONSE_HEADERS
    }
