"""MiniGate as an OAuth client to an upstream.

Every request is mocked. The live flow needs a browser and is driven by
`minigate oauth-probe`; what is asserted here is the shape of what MiniGate sends —
above all that it requests the resource the *upstream* owns, which is the single thing
a passthrough gateway cannot do and the reason the bridge exists.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from minigate.oauth_client import (
    ClientRegistration,
    OAuthError,
    PkcePair,
    TokenSet,
    UpstreamOAuth,
    discover,
)

UPSTREAM_RESOURCE = "https://mcp.linear.app/mcp"
ISSUER = "https://mcp.linear.app"
REDIRECT = "http://127.0.0.1:51234/callback"

AS_METADATA = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/authorize",
    "token_endpoint": f"{ISSUER}/token",
    "registration_endpoint": f"{ISSUER}/register",
    "scopes_supported": ["read", "write", "openid", "email"],
    "code_challenge_methods_supported": ["S256"],
    "resource": UPSTREAM_RESOURCE,
}

PRM = {
    "resource": UPSTREAM_RESOURCE,
    "authorization_servers": [ISSUER],
    "scopes_supported": ["read", "write"],
}

REGISTRATION = ClientRegistration(client_id="cid-123")


# ── PKCE ─────────────────────────────────────────────────────────────


async def test_pkce_challenge_is_derived_from_the_verifier():
    import base64
    import hashlib

    pair = PkcePair.generate()
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(pair.verifier.encode("ascii")).digest())
        .decode()
        .rstrip("=")
    )
    assert pair.challenge == expected


async def test_pkce_pairs_are_unique_and_unpadded():
    a, b = PkcePair.generate(), PkcePair.generate()
    assert a.verifier != b.verifier
    assert 43 <= len(a.verifier) <= 128
    assert "=" not in a.verifier and "=" not in a.challenge


# ── discovery ────────────────────────────────────────────────────────


def _discovery_transport(prm=PRM, as_meta=AS_METADATA, prm_status=200):
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(prm_status, json=prm)
        if path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, json=as_meta)
        return httpx.Response(404)

    return httpx.MockTransport(handler)


async def test_discovery_reads_both_documents():
    client = httpx.AsyncClient(transport=_discovery_transport())
    found = await discover(UPSTREAM_RESOURCE, client=client)
    assert found["issuer"] == ISSUER
    assert found["resource_metadata"]["resource"] == UPSTREAM_RESOURCE
    assert found["authorization_server"]["token_endpoint"] == f"{ISSUER}/token"


async def test_discovery_builds_the_rfc9728_path_from_the_resource_path():
    """The resource path goes after the well-known segment, not before it."""
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        if request.url.path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(200, json=PRM)
        return httpx.Response(200, json=AS_METADATA)

    await discover(UPSTREAM_RESOURCE, client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert "/.well-known/oauth-protected-resource/mcp" in seen


async def test_discovery_without_an_authorization_server_is_an_error():
    client = httpx.AsyncClient(transport=_discovery_transport(prm={"resource": UPSTREAM_RESOURCE}))
    with pytest.raises(OAuthError, match="no authorization_servers"):
        await discover(UPSTREAM_RESOURCE, client=client)


async def test_unreachable_metadata_is_an_error_not_a_crash():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(OAuthError, match="Could not reach"):
        await discover(UPSTREAM_RESOURCE, client=client)


# ── registration ─────────────────────────────────────────────────────


async def test_registration_sends_a_usable_native_client_record():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(201, json={"client_id": "cid-123"})

    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    registration = await flow.register()

    assert registration.client_id == "cid-123"
    assert registration.is_confidential is False
    assert captured["redirect_uris"] == [REDIRECT]
    assert "authorization_code" in captured["grant_types"]
    assert "refresh_token" in captured["grant_types"]
    # Identity scopes are not what the MCP resource is protected by.
    assert "openid" not in captured["scope"]
    assert "read" in captured["scope"] and "write" in captured["scope"]


async def test_registration_keeps_a_secret_when_one_is_issued():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"client_id": "cid", "client_secret": "shh"})

    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    assert (await flow.register()).is_confidential is True


async def test_registration_failure_reports_the_status():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="invalid_redirect_uri")

    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(OAuthError, match="invalid_redirect_uri"):
        await flow.register()


async def test_registration_requires_an_endpoint():
    flow = UpstreamOAuth({**AS_METADATA, "registration_endpoint": None}, UPSTREAM_RESOURCE, REDIRECT)
    with pytest.raises(OAuthError, match="no registration_endpoint"):
        await flow.register()
    await flow.aclose()


# ── authorization URL ────────────────────────────────────────────────


async def test_authorize_url_requests_the_upstreams_own_resource():
    """The whole point of the bridge.

    A passthrough gateway must advertise its own identifier under RFC 9728, so the
    client propagates *that* as the resource and the upstream will not honour the
    resulting token. As a client in its own right, MiniGate asks for the identifier the
    upstream actually owns.
    """
    flow = UpstreamOAuth(AS_METADATA, UPSTREAM_RESOURCE, REDIRECT)
    params = parse_qs(urlparse(flow.authorize_url(REGISTRATION, PkcePair.generate(), "st")).query)
    assert params["resource"] == [UPSTREAM_RESOURCE]
    await flow.aclose()


async def test_authorize_url_carries_pkce_and_state():
    flow = UpstreamOAuth(AS_METADATA, UPSTREAM_RESOURCE, REDIRECT)
    pkce = PkcePair.generate()
    params = parse_qs(urlparse(flow.authorize_url(REGISTRATION, pkce, "state-xyz")).query)

    assert params["response_type"] == ["code"]
    assert params["client_id"] == ["cid-123"]
    assert params["redirect_uri"] == [REDIRECT]
    assert params["state"] == ["state-xyz"]
    assert params["code_challenge"] == [pkce.challenge]
    assert params["code_challenge_method"] == ["S256"]
    # The verifier must never appear in a URL the user's browser follows.
    assert pkce.verifier not in str(params)
    await flow.aclose()


async def test_identity_scopes_are_requested_when_the_server_offers_them():
    """Without an id_token the audit trail cannot name the human who consented."""
    flow = UpstreamOAuth(AS_METADATA, UPSTREAM_RESOURCE, REDIRECT)
    params = parse_qs(urlparse(flow.authorize_url(REGISTRATION, PkcePair.generate(), "s")).query)
    granted = params["scope"][0].split()
    assert "read" in granted and "write" in granted
    assert "openid" in granted and "email" in granted
    await flow.aclose()


async def test_only_scopes_the_server_offers_are_requested():
    """Asking for a scope the server does not advertise is how a consent screen errors."""
    meta = {**AS_METADATA, "scopes_supported": ["read"]}
    flow = UpstreamOAuth(meta, UPSTREAM_RESOURCE, REDIRECT)
    params = parse_qs(urlparse(flow.authorize_url(REGISTRATION, PkcePair.generate(), "s")).query)
    assert params["scope"] == ["read"]
    await flow.aclose()


# ── token exchange ───────────────────────────────────────────────────


def _token_transport(captured: dict, payload: dict, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        captured.update({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
        return httpx.Response(status, json=payload) if status == 200 else httpx.Response(
            status, text=json.dumps(payload)
        )

    return httpx.MockTransport(handler)


async def test_exchange_sends_the_verifier_and_the_resource():
    captured: dict = {}
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport(captured, {"access_token": "tok"})),
    )
    pkce = PkcePair.generate()
    tokens = await flow.exchange(REGISTRATION, "the-code", pkce)

    assert tokens.access_token == "tok"
    assert captured["grant_type"] == "authorization_code"
    assert captured["code"] == "the-code"
    assert captured["code_verifier"] == pkce.verifier
    assert captured["resource"] == UPSTREAM_RESOURCE
    assert captured["redirect_uri"] == REDIRECT


async def test_exchange_parses_the_full_token_set():
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport({}, {
            "access_token": "tok", "token_type": "Bearer",
            "refresh_token": "ref", "expires_in": 3600, "scope": "read write",
        })),
    )
    tokens = await flow.exchange(REGISTRATION, "c", PkcePair.generate())
    assert tokens.refresh_token == "ref"
    assert tokens.expires_in == 3600
    assert tokens.authorization_header == "Bearer tok"


async def test_refresh_uses_the_refresh_grant_and_keeps_the_resource():
    captured: dict = {}
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport(captured, {"access_token": "new"})),
    )
    assert (await flow.refresh(REGISTRATION, "ref-1")).access_token == "new"
    assert captured["grant_type"] == "refresh_token"
    assert captured["refresh_token"] == "ref-1"
    assert captured["resource"] == UPSTREAM_RESOURCE


async def test_a_confidential_client_sends_its_secret():
    captured: dict = {}
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport(captured, {"access_token": "t"})),
    )
    await flow.exchange(ClientRegistration(client_id="c", client_secret="shh"), "code", PkcePair.generate())
    assert captured["client_secret"] == "shh"


async def test_a_token_response_without_a_token_is_an_error():
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport({}, {"token_type": "Bearer"})),
    )
    with pytest.raises(OAuthError, match="no access_token"):
        await flow.exchange(REGISTRATION, "c", PkcePair.generate())


async def test_a_rejected_exchange_surfaces_the_oauth_error_code():
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(
            transport=_token_transport({}, {"error": "invalid_grant"}, status=400)
        ),
    )
    with pytest.raises(OAuthError, match="invalid_grant"):
        await flow.exchange(REGISTRATION, "stale", PkcePair.generate())


# ── token hygiene ────────────────────────────────────────────────────


async def test_describe_never_reveals_the_token():
    secret = "super-secret-token-value"
    summary = TokenSet(access_token=secret, refresh_token="r", expires_in=60).describe()
    assert secret not in summary
    assert "len=24" in summary
    assert "opaque" in summary


async def test_describe_recognises_a_jwt_without_printing_it():
    summary = TokenSet(access_token="aaa.bbb.ccc").describe()
    assert "jwt" in summary
    assert "aaa.bbb.ccc" not in summary


# ── token_type is a diagnostic, not a detail ─────────────────────────
#
# It goes into the Authorization header verbatim. A scheme the resource server will
# not parse produces a 401 indistinguishable from a rejected token unless the value
# is visible.


async def test_describe_reports_the_token_type():
    summary = TokenSet(access_token="a" * 86, token_type="Bearer").describe()
    assert "type='Bearer'" in summary


async def test_an_unexpected_token_type_is_preserved_not_normalised():
    """Only bearer is canonicalised; rewriting anything else would hide a real signal."""
    tokens = TokenSet(access_token="t", token_type="mcp")
    assert tokens.authorization_header == "mcp t"
    assert "type='mcp'" in tokens.describe()


async def test_a_missing_token_type_defaults_to_bearer():
    captured: dict = {}
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport(captured, {"access_token": "t"})),
    )
    assert (await flow.exchange(REGISTRATION, "c", PkcePair.generate())).token_type == "Bearer"


async def test_unrecognised_response_fields_are_recorded_by_name_only():
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport({}, {
            "access_token": "t", "workspace": "acme",
        })),
    )
    tokens = await flow.exchange(REGISTRATION, "c", PkcePair.generate())
    # id_token is consumed for identity, so only genuinely unknown keys are listed.
    assert tokens.extra_fields == ("workspace",)
    summary = tokens.describe()
    assert "workspace" in summary
    assert "acme" not in summary


# ── bearer scheme canonicalisation ───────────────────────────────────
#
# Linear's token endpoint answers token_type "bearer" while its resource server accepts
# only "Bearer". Sent verbatim, the credential is never parsed and the 401 looks like a
# rejected token rather than an unread one.


async def test_a_lowercase_bearer_token_type_is_canonicalised_on_the_wire():
    tokens = TokenSet(access_token="tok", token_type="bearer")
    assert tokens.authorization_header == "Bearer tok"


async def test_any_casing_of_bearer_is_canonicalised():
    for given in ("bearer", "Bearer", "BEARER", "BeArEr"):
        assert TokenSet(access_token="t", token_type=given).authorization_header == "Bearer t"


async def test_the_observed_token_type_is_still_reported_verbatim():
    """Normalising the wire format must not hide what the server actually said."""
    tokens = TokenSet(access_token="t", token_type="bearer")
    assert tokens.token_type == "bearer"
    assert "type='bearer'" in tokens.describe()


async def test_a_non_bearer_scheme_is_passed_through_untouched():
    """Only the bearer scheme is canonicalised; anything else stays visible."""
    tokens = TokenSet(access_token="t", token_type="DPoP")
    assert tokens.authorization_header == "DPoP t"


async def test_an_exchanged_lowercase_token_reaches_the_wire_capitalised():
    flow = UpstreamOAuth(
        AS_METADATA, UPSTREAM_RESOURCE, REDIRECT,
        client=httpx.AsyncClient(transport=_token_transport({}, {
            "access_token": "abc", "token_type": "bearer",
        })),
    )
    tokens = await flow.exchange(REGISTRATION, "code", PkcePair.generate())
    assert tokens.authorization_header.startswith("Bearer ")


# ── identity from the id_token ───────────────────────────────────────


def _id_token(claims: dict) -> str:
    """A JWT with the given payload. The signature is not meaningful here."""
    import base64
    import json as _json

    def seg(obj):
        raw = _json.dumps(obj).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{seg({'alg': 'RS256'})}.{seg(claims)}.not-a-real-signature"


async def test_identity_claims_are_read_from_the_id_token():
    tokens = TokenSet(access_token="t", id_token=_id_token({
        "sub": "user_123", "email": "alice@acme.com", "name": "Alice", "iat": 1,
    }))
    identity = tokens.identity()
    assert identity["sub"] == "user_123"
    assert identity["email"] == "alice@acme.com"
    assert identity["name"] == "Alice"
    assert "iat" not in identity          # only the claims we attribute by


async def test_no_id_token_means_no_identity():
    assert TokenSet(access_token="t").identity() == {}


@pytest.mark.parametrize("bad", ["not-a-jwt", "a.b", "a.!!!.c", "...."])
async def test_a_malformed_id_token_yields_no_identity_rather_than_raising(bad):
    """An unparseable token must degrade to anonymous, never break the flow."""
    assert TokenSet(access_token="t", id_token=bad).identity() == {}


async def test_the_id_token_itself_is_never_printed():
    tokens = TokenSet(access_token="t", id_token=_id_token({"sub": "s", "email": "e@x.com"}))
    assert tokens.id_token not in tokens.describe()
