"""Prove MiniGate can obtain a usable upstream token on its own behalf.

Step 1 of the bridge. It answers one question and nothing else: when MiniGate is the
OAuth client — asking for the resource the upstream actually owns, rather than relaying
a request for MiniGate's own identifier — does the resulting token work against the
upstream's MCP endpoint?

If it does, the diagnosis of the connector failure is demonstrated rather than inferred,
and building the authorization-server half is justified. If it does not, the bridge would
not have worked either, and that is worth knowing before writing any of it.

Interactive by necessity: the consent screen is a browser flow. Nothing is persisted —
the token is used once and discarded, so this leaves no credential behind.
"""

from __future__ import annotations

import asyncio
import http.server
import json
import secrets
import socket
import threading
import urllib.parse
import webbrowser
from typing import Any

import httpx

from minigate.logging import logger
from minigate.oauth_client import OAuthError, PkcePair, UpstreamOAuth, discover

_CALLBACK_HOST = "127.0.0.1"
_CALLBACK_TIMEOUT_SECONDS = 300.0

_PAGE = """<!doctype html><meta charset=utf-8>
<title>MiniGate</title>
<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem">
<h2 style="color:#0a7d6b">{heading}</h2><p>{detail}</p>
<p style="color:#6b7784;font-size:.9rem">You can close this tab and return to the terminal.</p>
"""


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    """Catches the single redirect the authorization server sends back."""

    result: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 — BaseHTTPRequestHandler's interface
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        _CallbackHandler.result = {k: v[0] for k, v in query.items()}

        if "code" in _CallbackHandler.result:
            heading, detail = "Authorized", "MiniGate received the authorization code."
        else:
            heading = "Authorization failed"
            detail = _CallbackHandler.result.get(
                "error_description", _CallbackHandler.result.get("error", "No code returned.")
            )

        body = _PAGE.format(heading=heading, detail=detail).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        """Silence the default stderr access log."""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind((_CALLBACK_HOST, 0))
        return int(s.getsockname()[1])


def _await_callback(server: http.server.HTTPServer) -> dict[str, str]:
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    thread.join(timeout=_CALLBACK_TIMEOUT_SECONDS)
    return _CallbackHandler.result


async def _run_probe(resource_url: str, *, open_browser: bool = True) -> int:
    """Drive discovery, registration, consent, exchange and one authenticated call.

    Args:
        resource_url: The upstream MCP endpoint, e.g. https://mcp.linear.app/mcp
        open_browser: Whether to launch the consent page automatically.

    Returns:
        0 if the token worked against the upstream, non-zero otherwise.
    """
    log = logger.bind(module="minigate.oauth")

    print(f"\n[1/5] Discovering {resource_url}")
    found = await discover(resource_url)
    prm, as_meta = found["resource_metadata"], found["authorization_server"]
    upstream_resource = prm.get("resource") or resource_url

    print(f"      issuer              : {found['issuer']}")
    print(f"      resource advertised : {upstream_resource}")
    print(f"      AS declares resource: {as_meta.get('resource', '(none)')}")
    print(f"      registration        : {as_meta.get('registration_endpoint', '(none)')}")

    # The crux. MiniGate asks for the identifier the upstream owns — which a passthrough
    # gateway cannot do, because RFC 9728 obliges it to advertise its own.
    port = _free_port()
    redirect_uri = f"http://{_CALLBACK_HOST}:{port}/callback"
    flow = UpstreamOAuth(as_meta, resource=upstream_resource, redirect_uri=redirect_uri)

    try:
        print("\n[2/5] Registering MiniGate as a client")
        registration = await flow.register()
        print(f"      client_id    : {registration.client_id}")
        print(f"      confidential : {registration.is_confidential}")

        pkce = PkcePair.generate()
        state = secrets.token_urlsafe(16)
        url = flow.authorize_url(registration, pkce, state)

        server = http.server.HTTPServer((_CALLBACK_HOST, port), _CallbackHandler)
        print(f"\n[3/5] Waiting for consent on {redirect_uri}")
        print(f"\n      {url}\n")
        if open_browser:
            webbrowser.open(url)

        callback = _await_callback(server)
        server.server_close()

        if "code" not in callback:
            detail = callback.get("error_description") or callback.get("error") or "timed out"
            print(f"      no authorization code returned: {detail}")
            return 1
        if callback.get("state") != state:
            print("      state mismatch — discarding this response")
            return 1
        print("      authorization code received")

        print("\n[4/5] Exchanging the code for a token")
        tokens = await flow.exchange(registration, callback["code"], pkce)
        print(f"      token: {tokens.describe()}")

        print(f"\n[5/5] Calling {resource_url} with it")
        response = await _authenticated_call(resource_url, tokens.authorization_header)
        print(f"      HTTP {response.status_code}")

        if response.status_code != 200:
            challenge = response.headers.get("www-authenticate", "")
            print(f"      www-authenticate: {challenge[:200]}")
            print()
            # RFC 6750 §3.1: a resource server omits the error code when the request
            # carried no authentication information at all. That distinction separates
            # "your token was rejected" from "nothing we could parse arrived" — and
            # only the first says anything about the bridge design.
            if "error=" in challenge:
                print("  FAILED — the upstream parsed the credential and rejected it.")
                print("  A token minted for the upstream's own resource is not being honoured,")
                print("  so the bridge would not fix the connector failure either.")
            else:
                print("  INCONCLUSIVE — the challenge carries no error code, so the upstream")
                print("  found no credential to evaluate (RFC 6750 §3.1). The token itself was")
                print("  never judged, and this says nothing about the bridge design.")
                print()
                print(f"  Sent with scheme {tokens.token_type!r}. Check the hop output above:")
                print("    · a cross-origin redirect strips Authorization — that is the cause")
                print("    · no redirects means the credential reached the server unparsed,")
                print("      which points at the header itself rather than the token")
            return 1

        tools = _tools_from(response)
        print(f"      tools returned: {len(tools)}")
        print("\n  SUCCESS — MiniGate obtained a token the upstream honours.")
        print("  The upstream leg of the bridge works: registering as a client in its own")
        print("  right and requesting the upstream's own resource yields a usable token.")
        print()
        print("  Note this differs from the connector path in two ways at once — the")
        print("  resource requested and the client identity — so it does not isolate which")
        print("  of them broke that flow. The bridge replaces both, so it holds either way.")
        log.info("Upstream OAuth probe succeeded for {resource}", resource=resource_url)
        return 0

    except OAuthError as e:
        print(f"\n  FAILED — {e}")
        return 1
    finally:
        await flow.aclose()


_MAX_REDIRECTS = 5


async def _authenticated_call(url: str, authorization: str) -> httpx.Response:
    """POST `tools/list` with a credential, following redirects deliberately.

    An HTTP client will not carry an `Authorization` header across an origin change —
    that is correct behaviour, and it means an automatic redirect turns an authenticated
    request into an anonymous one. The resource server then answers "no credential",
    which is indistinguishable from a bad token unless the hops are visible.

    So redirects are followed by hand: the header is re-attached on same-origin hops and
    withheld across origins, and every hop is printed.
    """
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    headers = {
        "Authorization": authorization,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        # Some upstreams branch on this; sending it removes one variable.
        "MCP-Protocol-Version": "2025-06-18",
    }

    current = url
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        for hop in range(_MAX_REDIRECTS):
            response = await client.post(current, json=body, headers=headers)
            location = response.headers.get("location")
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                if hop:
                    print(f"      followed {hop} redirect(s), final URL {current}")
                return response

            target = str(httpx.URL(current).join(location))
            same_origin = httpx.URL(target).netloc == httpx.URL(current).netloc
            print(f"      {response.status_code} redirect -> {target}")
            if not same_origin:
                print("      cross-origin: Authorization withheld, per RFC 7235")
                headers.pop("Authorization", None)
            current = target

    print(f"      stopped after {_MAX_REDIRECTS} redirects")
    return response


def _tools_from(response: httpx.Response) -> list[dict[str, Any]]:
    """Pull the tool list out of a JSON or SSE response."""
    content_type = response.headers.get("content-type", "")
    payloads: list[Any] = []
    if "text/event-stream" in content_type:
        for block in response.text.split("\n\n"):
            data = "\n".join(
                line[5:].lstrip() for line in block.splitlines() if line.startswith("data:")
            )
            if data:
                try:
                    payloads.append(json.loads(data))
                except json.JSONDecodeError:
                    continue
    else:
        try:
            payloads.append(response.json())
        except ValueError:
            return []

    for item in payloads:
        for msg in item if isinstance(item, list) else [item]:
            if isinstance(msg, dict) and isinstance((msg.get("result") or {}).get("tools"), list):
                return msg["result"]["tools"]
    return []


def run_probe(resource_url: str, *, open_browser: bool = True) -> int:
    """Synchronous entry point for the CLI."""
    return asyncio.run(_run_probe(resource_url, open_browser=open_browser))
