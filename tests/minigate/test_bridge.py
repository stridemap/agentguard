"""The OAuth bridge: MiniGate as an authorization server, and as a client upstream.

The upstream is mocked throughout. What matters here is that each leg asks for a resource
its own authorization server owns, that the two PKCE pairs never cross, and that a token
MiniGate issued is swapped for the upstream credential before anything leaves the gateway.
"""

from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient

from agentguard.policy_engine import PolicyEngine
from minigate.bridge import OAuthBridge, swap_authorization
from minigate.bridge_store import (
    Grant,
    InMemoryGrantStore,
    RegisteredClient,
    UpstreamClient,
    new_token,
)
from minigate.config import AuthSettings, GatewayConfig, HttpSettings, ServerConfig
from minigate.core import GatewayCore
from minigate.guardrails import DLPSettings, Guardrails, InjectionSettings
from minigate.http_gateway import GatewayApp, create_app
from minigate.oauth_client import PkcePair, TokenSet

GATEWAY = "https://gw.example"
UPSTREAM = "https://mcp.vendor.example/mcp"
ISSUER = "https://mcp.vendor.example"
CLIENT_REDIRECT = "https://claude.ai/api/mcp/auth_callback"

POLICY_YAML = """
rules:
  - id: MG-900
    name: Allow
    priority: 900
    action: ALLOW
    conditions: {}
"""

AS_METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "registration_endpoint": f"{ISSUER}/register",
    "scopes_supported": ["read", "write"],
    "resource": UPSTREAM,
}
PRM = {
    "resource": UPSTREAM,
    "authorization_servers": [ISSUER],
    "scopes_supported": ["read", "write"],
}


class Upstream:
    """Stands in for the vendor's authorization server and MCP endpoint."""

    def __init__(self) -> None:
        self.authorize_params: dict[str, str] = {}
        self.token_params: dict[str, str] = {}
        self.mcp_headers: dict[str, str] = {}
        self.access_token = "upstream-access-token"

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(200, json=PRM)
        if path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, json=AS_METADATA)
        if path == "/register":
            return httpx.Response(201, json={"client_id": "minigate-upstream-client"})
        if path == "/token":
            self.token_params = {
                k: v[0] for k, v in parse_qs(request.content.decode()).items()
            }
            return httpx.Response(
                200,
                json={
                    "access_token": self.access_token,
                    "token_type": "bearer",
                    "refresh_token": "upstream-refresh",
                    "expires_in": 3600,
                    "scope": "read write",
                },
            )
        if path == "/mcp":
            self.mcp_headers = dict(request.headers)
            return httpx.Response(
                200,
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"tools": []},
                },
            )
        return httpx.Response(404)


@pytest.fixture
def upstream():
    return Upstream()


@pytest.fixture
def app_state(tmp_path, upstream):
    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_YAML, encoding="utf-8")
    config = GatewayConfig(
        http=HttpSettings(
            public_url=GATEWAY, auth=AuthSettings(mode="bridge", require=True)
        ),
        servers={"vendor": ServerConfig(url=UPSTREAM)},
    )
    core = GatewayCore(
        server="vendor",
        policy=PolicyEngine(str(policy)),
        guardrails=Guardrails(
            DLPSettings(enabled=False), InjectionSettings(enabled=False)
        ),
    )
    bridge = OAuthBridge(
        config,
        InMemoryGrantStore(),
        client=httpx.AsyncClient(transport=httpx.MockTransport(upstream.handler)),
    )
    return GatewayApp(
        config=config,
        cores={"vendor": core},
        client=httpx.AsyncClient(transport=httpx.MockTransport(upstream.handler)),
        bridge=bridge,
    )


@pytest.fixture
def client(app_state):
    with TestClient(create_app(app_state), follow_redirects=False) as c:
        yield c


def _register(client) -> str:
    r = client.post(
        "/oauth/register",
        json={
            "client_name": "Claude",
            "redirect_uris": [CLIENT_REDIRECT],
        },
    )
    assert r.status_code == 201
    return r.json()["client_id"]


def _authorize(client, client_id, **extra) -> httpx.Response:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": CLIENT_REDIRECT,
        "state": "client-state",
        "code_challenge": "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm8",
        "code_challenge_method": "S256",
        "resource": f"{GATEWAY}/mcp/vendor",
        **extra,
    }
    return client.get("/oauth/authorize", params=params)


# ── discovery ────────────────────────────────────────────────────────


def test_the_gateway_advertises_itself_as_the_authorization_server(client):
    """The fix in one assertion: in bridge mode we are the AS, not the upstream."""
    meta = client.get("/.well-known/oauth-protected-resource/mcp/vendor").json()
    assert meta["resource"] == f"{GATEWAY}/mcp/vendor"
    assert meta["authorization_servers"] == [GATEWAY]


def test_authorization_server_metadata_is_served(client):
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert meta["issuer"] == GATEWAY
    assert meta["token_endpoint"] == f"{GATEWAY}/oauth/token"
    assert meta["code_challenge_methods_supported"] == ["S256"]


# ── registration ─────────────────────────────────────────────────────


def test_a_client_can_register(client):
    assert _register(client)


def test_registration_requires_redirect_uris(client):
    r = client.post("/oauth/register", json={"client_name": "x"})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_redirect_uri"


# ── authorize ────────────────────────────────────────────────────────


def test_authorize_redirects_to_the_upstream_asking_for_its_own_resource(
    client, upstream
):
    """Each leg requests the resource its own authorization server owns."""
    r = _authorize(client, _register(client))
    assert r.status_code == 302

    params = parse_qs(urlparse(r.headers["location"]).query)
    assert params["resource"] == [UPSTREAM]
    assert params["client_id"] == ["minigate-upstream-client"]
    assert params["code_challenge_method"] == ["S256"]


def test_the_upstream_never_sees_the_clients_pkce_challenge(client):
    """Two PKCE pairs are in play; crossing them would break one leg or both."""
    client_challenge = "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm8"
    r = _authorize(client, _register(client), code_challenge=client_challenge)
    params = parse_qs(urlparse(r.headers["location"]).query)
    assert params["code_challenge"] != [client_challenge]


def test_an_unknown_client_is_refused(client):
    r = _authorize(client, "never-registered")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_client"


def test_an_unregistered_redirect_uri_is_refused_without_redirecting(client):
    """An open redirector on an authorization server hands out authorization codes."""
    r = _authorize(
        client, _register(client), redirect_uri="https://attacker.example/steal"
    )
    assert r.status_code == 400
    assert "location" not in r.headers


def test_a_resource_naming_no_governed_server_is_refused(client):
    r = _authorize(client, _register(client), resource="https://elsewhere.example/mcp")
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_target"


# ── callback and token ───────────────────────────────────────────────


def _full_flow(client, upstream) -> tuple[str, str]:
    """Register, authorize, complete the upstream callback. Returns (code, client_id)."""
    client_id = _register(client)
    redirect = _authorize(client, client_id)
    session_id = parse_qs(urlparse(redirect.headers["location"]).query)["state"][0]

    back = client.get(
        "/oauth/callback", params={"code": "upstream-code", "state": session_id}
    )
    assert back.status_code == 302
    assert back.headers["location"].startswith(CLIENT_REDIRECT)
    returned = parse_qs(urlparse(back.headers["location"]).query)
    assert returned["state"] == ["client-state"]
    return returned["code"][0], client_id


def test_the_callback_exchanges_upstream_code_and_issues_ours(client, upstream):
    code, _ = _full_flow(client, upstream)
    assert code
    # MiniGate's exchange with the upstream asked for the upstream's resource.
    assert upstream.token_params["resource"] == UPSTREAM
    assert upstream.token_params["grant_type"] == "authorization_code"


def test_our_code_is_exchanged_for_our_own_token_not_the_upstreams(client, upstream):
    """The client must never receive the upstream's credential.

    That separation is the whole point: the token a client holds is ours, scoped to us
    and revocable by us, and it is exchanged for the upstream's only inside the gateway.
    """
    pkce = PkcePair.generate()
    client_id = _register(client)
    redirect = _authorize(client, client_id, code_challenge=pkce.challenge)
    session_id = parse_qs(urlparse(redirect.headers["location"]).query)["state"][0]
    back = client.get(
        "/oauth/callback", params={"code": "upstream-code", "state": session_id}
    )
    code = parse_qs(urlparse(back.headers["location"]).query)["code"][0]

    r = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": CLIENT_REDIRECT,
            "code_verifier": pkce.verifier,
        },
    )
    assert r.status_code == 200, r.text
    issued = r.json()

    assert issued["token_type"] == "Bearer"
    assert issued["access_token"]
    assert issued["access_token"] != upstream.access_token
    assert upstream.access_token not in json.dumps(issued)
    # Credentials must not be cached by intermediaries (RFC 6749 §5.1).
    assert r.headers["cache-control"] == "no-store"


def test_a_wrong_pkce_verifier_is_refused(client, upstream):
    pkce = PkcePair.generate()
    client_id = _register(client)
    redirect = _authorize(client, client_id, code_challenge=pkce.challenge)
    session_id = parse_qs(urlparse(redirect.headers["location"]).query)["state"][0]
    back = client.get(
        "/oauth/callback", params={"code": "upstream-code", "state": session_id}
    )
    code = parse_qs(urlparse(back.headers["location"]).query)["code"][0]

    r = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": CLIENT_REDIRECT,
            "code_verifier": PkcePair.generate().verifier,
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


def test_the_issued_token_then_works_against_the_gateway(client, upstream):
    """End to end: register, consent, exchange, and call through the governed path."""
    pkce = PkcePair.generate()
    client_id = _register(client)
    redirect = _authorize(client, client_id, code_challenge=pkce.challenge)
    session_id = parse_qs(urlparse(redirect.headers["location"]).query)["state"][0]
    back = client.get(
        "/oauth/callback", params={"code": "upstream-code", "state": session_id}
    )
    code = parse_qs(urlparse(back.headers["location"]).query)["code"][0]

    issued = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": client_id,
            "redirect_uri": CLIENT_REDIRECT,
            "code_verifier": pkce.verifier,
        },
    ).json()["access_token"]

    r = client.post(
        "/mcp/vendor",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {issued}"},
    )
    assert r.status_code == 200
    assert upstream.mcp_headers["authorization"] == "Bearer upstream-access-token"


def test_a_replayed_authorization_code_is_refused(client, upstream):
    code, client_id = _full_flow(client, upstream)
    body = {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "redirect_uri": CLIENT_REDIRECT,
        "code_verifier": "v" * 43,
    }
    client.post("/oauth/token", data=body)
    again = client.post("/oauth/token", data=body)
    assert again.status_code == 400
    assert again.json()["error"] == "invalid_grant"


def test_a_replayed_callback_finds_no_session(client, upstream):
    client_id = _register(client)
    redirect = _authorize(client, client_id)
    session_id = parse_qs(urlparse(redirect.headers["location"]).query)["state"][0]

    client.get("/oauth/callback", params={"code": "c", "state": session_id})
    again = client.get("/oauth/callback", params={"code": "c", "state": session_id})
    assert again.status_code == 400
    assert again.json()["error"] == "invalid_request"


def test_an_unsupported_grant_type_is_refused(client):
    r = client.post("/oauth/token", data={"grant_type": "password", "code": "x"})
    assert r.status_code == 400
    assert r.json()["error"] == "unsupported_grant_type"


# ── the swap ─────────────────────────────────────────────────────────


def _grant_with_token(app_state, access="our-token") -> Grant:
    grant = Grant(
        grant_id=new_token(8),
        client_id="cid",
        server_name="vendor",
        upstream=TokenSet(access_token="upstream-access-token", token_type="bearer"),
        access_token=access,
    )
    app_state.bridge.store.put_grant(grant)
    return grant


def test_our_token_is_swapped_for_the_upstream_credential(app_state, upstream):
    _grant_with_token(app_state)
    with TestClient(create_app(app_state)) as c:
        r = c.post(
            "/mcp/vendor",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer our-token"},
        )
    assert r.status_code == 200
    # The upstream saw its own credential, canonicalised — never ours.
    assert upstream.mcp_headers["authorization"] == "Bearer upstream-access-token"
    assert "our-token" not in json.dumps(upstream.mcp_headers)


def test_an_unrecognised_token_never_reaches_the_upstream(app_state, upstream):
    with TestClient(create_app(app_state)) as c:
        r = c.post(
            "/mcp/vendor",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer not-ours"},
        )
    assert r.status_code == 401
    assert "invalid_token" in r.headers["www-authenticate"]
    assert upstream.mcp_headers == {}


def test_a_revoked_token_stops_working(app_state):
    _grant_with_token(app_state, access="doomed")
    app_state.bridge.store.revoke("doomed")
    with TestClient(create_app(app_state)) as c:
        r = c.post(
            "/mcp/vendor",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer doomed"},
        )
    assert r.status_code == 401


async def test_swap_rejects_a_missing_or_malformed_header(app_state):
    for presented in (None, "", "Basic abc", "our-token"):
        header, grant = await swap_authorization(app_state.bridge, presented)
        assert header is None and grant is None


# ── store semantics ──────────────────────────────────────────────────


def test_redirect_uris_match_exactly_not_by_prefix():
    """Prefix matching on redirect URIs is how open redirectors get built."""
    c = RegisteredClient(client_id="x", redirect_uris=("https://ok.example/cb",))
    assert c.allows("https://ok.example/cb")
    assert not c.allows("https://ok.example/cb/../evil")
    assert not c.allows("https://ok.example/cb?next=https://evil")
    assert not c.allows("https://ok.example")


def test_an_authorization_code_is_single_use():
    store = InMemoryGrantStore()
    grant = Grant(
        grant_id="g",
        client_id="c",
        server_name="s",
        upstream=TokenSet(access_token="u"),
        code="the-code",
    )
    store.put_grant(grant)
    assert store.take_by_code("the-code") is not None
    assert store.take_by_code("the-code") is None


def test_an_expired_authorization_code_is_refused():
    import minigate.bridge_store as bs

    store = bs.InMemoryGrantStore()
    grant = bs.Grant(
        grant_id="g",
        client_id="c",
        server_name="s",
        upstream=TokenSet(access_token="u"),
        code="old",
        created_at=0.0,
    )
    store.put_grant(grant)
    assert store.take_by_code("old") is None


def test_an_expired_session_is_not_returned():
    import minigate.bridge_store as bs

    store = bs.InMemoryGrantStore()
    store.put_session(
        bs.AuthSession(
            session_id="s",
            client_id="c",
            server_name="v",
            client_redirect_uri=CLIENT_REDIRECT,
            client_state=None,
            client_code_challenge=None,
            client_code_challenge_method="S256",
            upstream_verifier="v",
            created_at=0.0,
        )
    )
    assert store.take_session("s") is None


# ── token lifetimes ──────────────────────────────────────────────────
#
# Two independent clocks: ours governs what the client may present to the gateway, the
# upstream's governs what the gateway may present to the vendor.


def _full_token(client, upstream=None):
    """Run the whole flow and return the issued token payload."""
    pkce = PkcePair.generate()
    client_id = _register(client)
    redirect = _authorize(client, client_id, code_challenge=pkce.challenge)
    session_id = parse_qs(urlparse(redirect.headers["location"]).query)["state"][0]
    back = client.get(
        "/oauth/callback", params={"code": "upstream-code", "state": session_id}
    )
    code = parse_qs(urlparse(back.headers["location"]).query)["code"][0]
    return (
        client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": CLIENT_REDIRECT,
                "code_verifier": pkce.verifier,
            },
        ).json(),
        client_id,
    )


def test_a_refresh_token_is_issued_to_the_client(client, upstream):
    issued, _ = _full_token(client, upstream)
    assert issued["refresh_token"]
    assert issued["refresh_token"] != issued["access_token"]
    # It is ours, not the vendor's.
    assert issued["refresh_token"] != "upstream-refresh"


def test_a_client_can_renew_with_its_refresh_token(client, upstream):
    issued, client_id = _full_token(client, upstream)
    renewed = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": issued["refresh_token"],
            "client_id": client_id,
        },
    )
    assert renewed.status_code == 200, renewed.text
    assert renewed.json()["access_token"] != issued["access_token"]


def test_both_tokens_rotate_on_refresh(client, upstream):
    """A refresh token that survives its own use is a long-lived bearer credential."""
    issued, client_id = _full_token(client, upstream)
    renewed = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": issued["refresh_token"],
            "client_id": client_id,
        },
    ).json()
    assert renewed["refresh_token"] != issued["refresh_token"]


def test_a_used_refresh_token_cannot_be_replayed(client, upstream):
    issued, client_id = _full_token(client, upstream)
    body = {
        "grant_type": "refresh_token",
        "refresh_token": issued["refresh_token"],
        "client_id": client_id,
    }
    assert client.post("/oauth/token", data=body).status_code == 200
    again = client.post("/oauth/token", data=body)
    assert again.status_code == 400
    assert again.json()["error"] == "invalid_grant"


def test_the_old_access_token_stops_working_after_refresh(client, upstream, app_state):
    issued, client_id = _full_token(client, upstream)
    client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": issued["refresh_token"],
            "client_id": client_id,
        },
    )
    with TestClient(create_app(app_state)) as c:
        r = c.post(
            "/mcp/vendor",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": f"Bearer {issued['access_token']}"},
        )
    assert r.status_code == 401


def test_a_refresh_token_from_another_client_is_refused(client, upstream):
    issued, _ = _full_token(client, upstream)
    other = _register(client)
    r = client.post(
        "/oauth/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": issued["refresh_token"],
            "client_id": other,
        },
    )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_grant"


async def test_an_expired_access_token_is_refused_and_dropped(app_state):
    grant = _grant_with_token(app_state, access="stale")
    grant.access_expires_at = 1.0  # long past
    app_state.bridge.store.put_grant(grant)

    header, _ = await swap_authorization(app_state.bridge, "Bearer stale")
    assert header is None
    assert app_state.bridge.store.get_by_access_token("stale") is None


async def test_a_near_expiry_upstream_credential_is_refreshed_before_use(
    app_state, upstream
):
    """The refresh token sits in the grant; this is the point it gets used."""
    grant = _grant_with_token(app_state, access="live")
    grant.upstream = TokenSet(
        access_token="old-upstream",
        token_type="bearer",
        refresh_token="upstream-refresh",
        expires_in=3600,
    )
    grant.upstream_expires_at = time.time() + 10  # inside the refresh margin
    app_state.bridge.store.put_grant(grant)

    header, _ = await swap_authorization(app_state.bridge, "Bearer live")
    assert header == "Bearer upstream-access-token"  # what the mocked upstream returns
    assert upstream.token_params["grant_type"] == "refresh_token"


async def test_a_healthy_upstream_credential_is_not_refreshed(app_state, upstream):
    grant = _grant_with_token(app_state, access="live")
    grant.upstream_expires_at = time.time() + 86400
    app_state.bridge.store.put_grant(grant)

    header, _ = await swap_authorization(app_state.bridge, "Bearer live")
    assert header == "Bearer upstream-access-token"
    assert upstream.token_params == {}  # no refresh was attempted


async def test_a_failed_upstream_refresh_still_attempts_the_call(app_state, upstream):
    """The upstream is the authority on whether its token is dead, not us."""
    grant = _grant_with_token(app_state, access="live")
    grant.upstream = TokenSet(
        access_token="maybe-still-good", token_type="bearer", refresh_token=None
    )  # nothing to refresh with
    grant.upstream_expires_at = time.time() - 1
    app_state.bridge.store.put_grant(grant)

    header, _ = await swap_authorization(app_state.bridge, "Bearer live")
    assert header == "Bearer maybe-still-good"


# ── redirect URI validation (RFC 8252) ───────────────────────────────
#
# An authorization code reaching the wrong place is enough to obtain a token, so the
# registered redirect targets are the security boundary of an open registration endpoint.


@pytest.mark.parametrize(
    "uri",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "http://127.0.0.1:51234/callback",
        "http://localhost:8080/cb",
        "com.example.app:/oauth",
    ],
)
def test_acceptable_redirect_uris(client, uri):
    r = client.post(
        "/oauth/register", json={"client_name": "x", "redirect_uris": [uri]}
    )
    assert r.status_code == 201, f"{uri} should be accepted: {r.text}"


@pytest.mark.parametrize(
    ("uri", "why"),
    [
        ("http://evil.example/cb", "plaintext off the loopback interface"),
        ("https://ok.example/cb#frag", "fragments are forbidden by RFC 6749 §3.1.2"),
        (
            "https://*.example.com/cb",
            "a wildcard turns an allowlist into an open redirector",
        ),
        ("/relative/path", "must be absolute"),
        ("https://ok.example/" + "a" * 3000, "absurdly long"),
    ],
)
def test_refused_redirect_uris(client, uri, why):
    r = client.post(
        "/oauth/register", json={"client_name": "x", "redirect_uris": [uri]}
    )
    assert r.status_code == 400, f"{uri} should be refused ({why})"
    assert r.json()["error"] == "invalid_redirect_uri"


def test_too_many_redirect_uris_are_refused(client):
    r = client.post(
        "/oauth/register",
        json={
            "client_name": "x",
            "redirect_uris": [f"https://ok.example/cb{i}" for i in range(20)],
        },
    )
    assert r.status_code == 400


# ── registration limits ──────────────────────────────────────────────


def test_registration_is_rate_limited(client):
    """Open registration without a limit is an unbounded growth vector."""
    codes = [
        client.post(
            "/oauth/register",
            json={"client_name": "flood", "redirect_uris": [CLIENT_REDIRECT]},
        ).status_code
        for _ in range(40)
    ]
    assert 201 in codes
    assert 429 in codes, "a flood of registrations should eventually be refused"


def test_the_limit_is_per_caller(app_state):
    """One noisy caller must not lock everyone else out."""
    from minigate.bridge import _REGISTRATIONS_PER_HOUR

    limiter = app_state.bridge._registrations
    for _ in range(_REGISTRATIONS_PER_HOUR):
        assert limiter.allow("1.2.3.4")
    assert not limiter.allow("1.2.3.4")
    assert limiter.allow("5.6.7.8")


def test_unused_clients_are_reclaimed_before_refusing(app_state):
    """A client that never completed consent holds nothing and is litter after a week."""
    import time as _t

    store = app_state.bridge.store
    for i in range(5):
        store.put_client(
            RegisteredClient(
                client_id=f"old{i}",
                redirect_uris=(CLIENT_REDIRECT,),
                created_at=_t.time() - 30 * 24 * 3600,
            )
        )
    assert store.count_clients() == 5
    assert store.purge_unused_clients(_t.time() - 7 * 24 * 3600) == 5
    assert store.count_clients() == 0


def test_a_client_with_a_grant_is_not_reclaimed(app_state):
    """Reclaiming a client that holds a live grant would break a working integration."""
    import time as _t

    store = app_state.bridge.store
    store.put_client(
        RegisteredClient(
            client_id="busy",
            redirect_uris=(CLIENT_REDIRECT,),
            created_at=_t.time() - 30 * 24 * 3600,
        )
    )
    _grant_with_token(app_state, access="live")  # grant.client_id == "cid"
    store.put_client(
        RegisteredClient(
            client_id="cid",
            redirect_uris=(CLIENT_REDIRECT,),
            created_at=_t.time() - 30 * 24 * 3600,
        )
    )

    store.purge_unused_clients(_t.time() - 7 * 24 * 3600)
    assert store.get_client("cid") is not None
    assert store.get_client("busy") is None


# ── stable upstream registration ─────────────────────────────────────


async def test_the_upstream_registration_is_persisted(app_state, upstream):
    """Re-registering on every boot mints a new client_id with the vendor each time."""

    server = ServerConfig(url=UPSTREAM)
    await app_state.bridge.upstream_flow(None, server, "vendor")

    stored = app_state.bridge.store.get_upstream_client("vendor")
    assert stored is not None
    assert stored.client_id == "minigate-upstream-client"


async def test_a_stored_upstream_registration_is_reused_after_restart(
    app_state, upstream
):
    """Simulates a redeploy: same store, fresh process state."""
    from minigate.bridge import OAuthBridge

    app_state.bridge.store.put_upstream_client(
        UpstreamClient(server_name="vendor", client_id="from-a-previous-run")
    )
    fresh = OAuthBridge(
        app_state.config,
        app_state.bridge.store,
        client=httpx.AsyncClient(transport=httpx.MockTransport(upstream.handler)),
    )
    await fresh.upstream_flow(None, ServerConfig(url=UPSTREAM), "vendor")
    assert fresh.upstream_registration("vendor").client_id == "from-a-previous-run"


# ── identity and audit ───────────────────────────────────────────────
#
# A gateway that records every tool call but not who was granted the right to make them
# answers "what happened" and never "who was allowed to".


def _jwt(claims: dict) -> str:
    import base64 as _b64
    import json as _json

    def seg(obj):
        return _b64.urlsafe_b64encode(_json.dumps(obj).encode()).decode().rstrip("=")

    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.sig"


@pytest.fixture
def identified_upstream(upstream):
    """An upstream whose token response carries an id_token."""
    original = upstream.handler

    def handler(request: httpx.Request) -> httpx.Response:
        response = original(request)
        if request.url.path == "/token":
            body = json.loads(response.content)
            body["id_token"] = _jwt({"sub": "lin_user_42", "email": "alice@acme.com"})
            return httpx.Response(200, json=body)
        return response

    upstream.handler = handler
    return upstream


@pytest.fixture
def audited(tmp_path, identified_upstream):
    """A bridge with a recording sink, over an identity-carrying upstream."""
    from minigate.bridge import OAuthBridge

    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_YAML, encoding="utf-8")
    config = GatewayConfig(
        http=HttpSettings(
            public_url=GATEWAY, auth=AuthSettings(mode="bridge", require=True)
        ),
        servers={"vendor": ServerConfig(url=UPSTREAM)},
    )
    events: list = []

    class Sink:
        def emit(self, event):
            events.append(event)

    core = GatewayCore(
        server="vendor",
        policy=PolicyEngine(str(policy)),
        sink=Sink(),
        guardrails=Guardrails(
            DLPSettings(enabled=False), InjectionSettings(enabled=False)
        ),
    )
    bridge = OAuthBridge(
        config,
        InMemoryGrantStore(),
        sink=Sink(),
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(identified_upstream.handler)
        ),
    )
    app = GatewayApp(
        config=config,
        cores={"vendor": core},
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(identified_upstream.handler)
        ),
        bridge=bridge,
    )
    return app, events


def test_the_consenting_user_is_captured_on_the_grant(audited):
    app_state, _ = audited
    with TestClient(create_app(app_state), follow_redirects=False) as c:
        issued, _ = _full_token(c, None)

    grant = app_state.bridge.store.get_by_access_token(issued["access_token"])
    assert grant.subject == "lin_user_42"
    assert grant.subject_email == "alice@acme.com"
    assert grant.principal == "alice@acme.com"


def test_a_grant_without_an_id_token_falls_back_to_the_client(app_state):
    """No identity available must degrade to the client, never to nothing."""
    grant = _grant_with_token(app_state, access="anon")
    assert grant.subject is None
    assert grant.principal.startswith("client:")


def test_authorization_and_issuance_are_audited(audited):
    app_state, events = audited
    with TestClient(create_app(app_state), follow_redirects=False) as c:
        _full_token(c, None)

    actions = [e.method for e in events]
    assert "oauth/authorize" in actions
    assert "oauth/token" in actions
    assert all(
        e.client_id == "alice@acme.com" for e in events if e.method.startswith("oauth/")
    )


def test_revocation_is_audited(audited):
    app_state, events = audited
    with TestClient(create_app(app_state), follow_redirects=False) as c:
        issued, _ = _full_token(c, None)
        events.clear()
        c.post("/oauth/revoke", data={"token": issued["access_token"]})

    revocations = [e for e in events if e.method == "oauth/revoke"]
    assert len(revocations) == 1
    assert revocations[0].policy_result == "BLOCK"
    assert revocations[0].client_id == "alice@acme.com"


def test_tool_calls_are_attributed_to_the_human_not_the_client(audited):
    """The payoff: an audit line names a person rather than an integration."""
    app_state, events = audited
    with TestClient(create_app(app_state), follow_redirects=False) as c:
        issued, _ = _full_token(c, None)
        events.clear()
        c.post(
            "/mcp/vendor",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {issued['access_token']}"},
        )

    tool_events = [e for e in events if e.method == "tools/call"]
    assert tool_events, "the call should have been governed and recorded"
    assert all(e.client_id == "alice@acme.com" for e in tool_events)


def test_an_unauthenticated_call_is_not_attributed_to_a_previous_user(audited):
    """A context variable leaking between requests would misattribute an action."""
    app_state, events = audited
    with TestClient(create_app(app_state), follow_redirects=False) as c:
        issued, _ = _full_token(c, None)
        c.post(
            "/mcp/vendor",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {}},
            },
            headers={"Authorization": f"Bearer {issued['access_token']}"},
        )
        events.clear()
        r = c.post(
            "/mcp/vendor",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "search", "arguments": {}},
            },
            headers={"Authorization": "Bearer not-a-real-token"},
        )

    assert r.status_code == 401
    assert not [e for e in events if e.client_id == "alice@acme.com"]


def test_a_broken_sink_does_not_break_authorization(audited):
    """Losing an audit record must not cost the user their authorization."""
    app_state, _ = audited

    class Exploding:
        def emit(self, event):
            raise RuntimeError("sink is down")

    app_state.bridge.sink = Exploding()
    with TestClient(create_app(app_state), follow_redirects=False) as c:
        issued, _ = _full_token(c, None)
    assert issued["access_token"]


# ── per-server mode ──────────────────────────────────────────────────
#
# A gateway fronting several upstreams generally needs both modes: bridge requires the
# upstream to let MiniGate register as an OAuth client, and not every vendor does.
# Google advertises no registration endpoint at all.


@pytest.fixture
def mixed(tmp_path, upstream):
    """One bridged server and one passthrough server behind the same gateway."""
    from minigate.bridge import OAuthBridge

    policy = tmp_path / "policy.yaml"
    policy.write_text(POLICY_YAML, encoding="utf-8")
    config = GatewayConfig(
        http=HttpSettings(
            public_url=GATEWAY, auth=AuthSettings(mode="bridge", require=True)
        ),
        servers={
            "vendor": ServerConfig(url=UPSTREAM),  # inherits bridge
            "nodcr": ServerConfig(
                url="https://nodcr.example/mcp",  # cannot be bridged
                auth_mode="passthrough",
                authorization_servers=["https://accounts.nodcr.example"],
            ),
        },
    )

    def core_for(name):
        return GatewayCore(
            server=name,
            policy=PolicyEngine(str(policy)),
            guardrails=Guardrails(
                DLPSettings(enabled=False), InjectionSettings(enabled=False)
            ),
        )

    bridge = OAuthBridge(
        config,
        InMemoryGrantStore(),
        client=httpx.AsyncClient(transport=httpx.MockTransport(upstream.handler)),
    )
    return GatewayApp(
        config=config,
        cores={"vendor": core_for("vendor"), "nodcr": core_for("nodcr")},
        client=httpx.AsyncClient(transport=httpx.MockTransport(upstream.handler)),
        bridge=bridge,
    )


def test_each_server_advertises_its_own_authorization_server(mixed):
    """The bridged one points at us; the other keeps pointing at its vendor."""
    with TestClient(create_app(mixed)) as c:
        bridged = c.get("/.well-known/oauth-protected-resource/mcp/vendor").json()
        direct = c.get("/.well-known/oauth-protected-resource/mcp/nodcr").json()

    assert bridged["authorization_servers"] == [GATEWAY]
    assert direct["authorization_servers"] == ["https://accounts.nodcr.example"]


def test_authorizing_against_a_non_bridged_server_is_refused_clearly(mixed):
    """Better than failing later at registration with 'no registration_endpoint'."""
    with TestClient(create_app(mixed), follow_redirects=False) as c:
        client_id = _register(c)
        r = c.get(
            "/oauth/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": CLIENT_REDIRECT,
                "state": "s",
                "code_challenge": "Z" * 43,
                "code_challenge_method": "S256",
                "resource": f"{GATEWAY}/mcp/nodcr",
            },
        )
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_target"
    assert "not configured for bridge mode" in r.json()["error_description"]


def test_a_passthrough_server_relays_the_callers_token_verbatim(mixed, upstream):
    """Switching one server to bridge must not change how the other authenticates."""
    with TestClient(create_app(mixed)) as c:
        c.post(
            "/mcp/nodcr",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer caller-own-token"},
        )
    assert upstream.mcp_headers.get("authorization") == "Bearer caller-own-token"


def test_the_bridged_server_still_requires_one_of_our_tokens(mixed, upstream):
    with TestClient(create_app(mixed)) as c:
        r = c.post(
            "/mcp/vendor",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer caller-own-token"},
        )
    assert r.status_code == 401


# ── two bridged upstreams behind one gateway ─────────────────────────
#
# MiniGate is one authorization server to its clients, and a separate OAuth client at
# each vendor. Those are different layers, and the distinction is the whole design.


LINEAR_LIKE = "https://alpha.example/mcp"
JIRA_LIKE = "https://beta.example/mcp"


class TwoVendors:
    """Two independent upstreams, each with its own authorization server."""

    def __init__(self) -> None:
        self.registered: list[str] = []
        self.authorized: list[tuple[str, str]] = []  # (host, resource)

    def handler(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(
                200,
                json={
                    "resource": f"https://{host}/mcp",
                    "authorization_servers": [f"https://{host}"],
                },
            )
        if path == "/.well-known/oauth-authorization-server":
            return httpx.Response(
                200,
                json={
                    "issuer": f"https://{host}",
                    "authorization_endpoint": f"https://{host}/authorize",
                    "token_endpoint": f"https://{host}/token",
                    "registration_endpoint": f"https://{host}/register",
                    "scopes_supported": ["read", "write"],
                },
            )
        if path == "/register":
            self.registered.append(host)
            return httpx.Response(201, json={"client_id": f"minigate-at-{host}"})
        if path == "/token":
            params = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.authorized.append((host, params.get("resource", "")))
            return httpx.Response(
                200,
                json={
                    "access_token": f"{host}-upstream-token",
                    "token_type": "bearer",
                },
            )
        return httpx.Response(
            200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}
        )


@pytest.fixture
def two_vendors(tmp_path):
    from minigate.bridge import OAuthBridge

    policy = tmp_path / "p.yaml"
    policy.write_text(POLICY_YAML, encoding="utf-8")
    vendors = TwoVendors()
    config = GatewayConfig(
        http=HttpSettings(
            public_url=GATEWAY, auth=AuthSettings(mode="bridge", require=True)
        ),
        servers={
            "alpha": ServerConfig(url=LINEAR_LIKE),
            "beta": ServerConfig(url=JIRA_LIKE),
        },
    )
    cores = {
        n: GatewayCore(
            server=n,
            policy=PolicyEngine(str(policy)),
            guardrails=Guardrails(
                DLPSettings(enabled=False), InjectionSettings(enabled=False)
            ),
        )
        for n in ("alpha", "beta")
    }
    bridge = OAuthBridge(
        config,
        InMemoryGrantStore(),
        client=httpx.AsyncClient(transport=httpx.MockTransport(vendors.handler)),
    )
    app = GatewayApp(
        config=config,
        cores=cores,
        bridge=bridge,
        client=httpx.AsyncClient(transport=httpx.MockTransport(vendors.handler)),
    )
    return app, vendors


def test_both_servers_share_one_minigate_authorization_server(two_vendors):
    """Downstream there is one AS: a client registers once, with us."""
    app, _ = two_vendors
    with TestClient(create_app(app)) as c:
        alpha = c.get("/.well-known/oauth-protected-resource/mcp/alpha").json()
        beta = c.get("/.well-known/oauth-protected-resource/mcp/beta").json()
        meta = c.get("/.well-known/oauth-authorization-server").json()

    assert alpha["authorization_servers"] == [GATEWAY]
    assert beta["authorization_servers"] == [GATEWAY]
    assert meta["issuer"] == GATEWAY  # one issuer for the whole service
    assert alpha["resource"] != beta["resource"]  # but distinct resources


def test_each_upstream_gets_its_own_registration_and_resource(two_vendors):
    """Upstream, each vendor is a separate authorization server and a separate client."""
    app, vendors = two_vendors
    with TestClient(create_app(app), follow_redirects=False) as c:
        client_id = _register(c)
        for name in ("alpha", "beta"):
            r = c.get(
                "/oauth/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": CLIENT_REDIRECT,
                    "state": "s",
                    "code_challenge": "Z" * 43,
                    "code_challenge_method": "S256",
                    "resource": f"{GATEWAY}/mcp/{name}",
                },
            )
            assert r.status_code == 302
            sid = parse_qs(urlparse(r.headers["location"]).query)["state"][0]
            c.get("/oauth/callback", params={"code": "c", "state": sid})

    assert sorted(vendors.registered) == ["alpha.example", "beta.example"]
    # Each exchange asked its own vendor for its own resource.
    assert ("alpha.example", LINEAR_LIKE) in vendors.authorized
    assert ("beta.example", JIRA_LIKE) in vendors.authorized


def test_a_token_for_one_server_does_not_work_against_the_other(two_vendors):
    """A grant is bound to one upstream; it is not a key to the whole gateway."""
    app, _ = two_vendors
    grant = Grant(
        grant_id="g",
        client_id="cid",
        server_name="alpha",
        upstream=TokenSet(access_token="alpha-token", token_type="bearer"),
        access_token="ours-for-alpha",
    )
    app.bridge.store.put_grant(grant)

    with TestClient(create_app(app)) as c:
        ok = c.post(
            "/mcp/alpha",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer ours-for-alpha"},
        )
        crossed = c.post(
            "/mcp/beta",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Authorization": "Bearer ours-for-alpha"},
        )

    assert (
        ok.status_code == 200
    ), "the token must work against the server it was issued for"
    assert crossed.status_code == 401, (
        "a token issued for alpha must not authorize beta — otherwise alpha's upstream "
        "credential is forwarded to an endpoint it was never issued for"
    )


# ── discovery variants ───────────────────────────────────────────────
#
# Clients differ in how they derive the authorization-server metadata URL: some from the
# issuer, some from the resource path, and MCP's later revisions permit OIDC Discovery.
# A client that cannot find this document reports only that it could not register, which
# points at the wrong endpoint entirely.


@pytest.mark.parametrize(
    "path",
    [
        "/.well-known/oauth-authorization-server",
        "/.well-known/oauth-authorization-server/mcp/vendor",
        "/.well-known/openid-configuration",
        "/.well-known/openid-configuration/mcp/vendor",
    ],
)
def test_authorization_server_metadata_is_found_at_every_variant(client, path):
    r = client.get(path)
    assert r.status_code == 200, f"{path} must serve AS metadata"
    assert r.json()["issuer"] == GATEWAY
    assert r.json()["registration_endpoint"] == f"{GATEWAY}/oauth/register"


def test_the_metadata_advertises_what_the_endpoints_actually_support(client):
    """A client that trusts this document and then fails is the worst outcome."""
    meta = client.get("/.well-known/oauth-authorization-server").json()
    assert "refresh_token" in meta["grant_types_supported"]  # /oauth/token honours it
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["token_endpoint_auth_methods_supported"] == ["none"]
    assert meta["revocation_endpoint"].endswith("/oauth/revoke")


@pytest.mark.parametrize(
    "redirect",
    [
        "https://claude.ai/api/mcp/auth_callback",
        "https://claude.com/api/mcp/auth_callback",
    ],
)
def test_a_claude_connector_can_register(client, redirect):
    """The exact shape a connector sends, including fields we do not use."""
    r = client.post(
        "/oauth/register",
        json={
            "client_name": "Claude",
            "redirect_uris": [redirect],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "web",
            "scope": "read write",
        },
    )
    assert r.status_code == 201, r.text
    assert r.json()["client_id"]
