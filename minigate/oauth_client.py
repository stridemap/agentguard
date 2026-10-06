"""MiniGate as an OAuth client to an upstream MCP server.

This is the first half of the bridge described in ADR-002's revision. Today MiniGate
relays the caller's token verbatim and mints nothing, which cannot work when the
upstream's authorization server serves exactly one resource and that resource is not
ours: RFC 9728 obliges us to advertise our own identifier, the client propagates it as
the RFC 8707 `resource`, and the upstream will not honour a token minted for a resource
it does not own.

The way out is for MiniGate to hold both roles — an authorization server to the client,
and an ordinary OAuth client to the upstream. This module is only the second role, kept
separate so the upstream leg can be proven on its own before any authorization-server
surface exists.

Every network call is async. The bridge's endpoints run in the gateway's event loop, and
a synchronous token exchange there blocks every other request in flight — measured at
four concurrent callbacks serialising behind a slow upstream. Blocking the loop to
authorize one user while another's tool call waits is not a trade worth making.

Deliberately not handled yet, because they belong with the authorization-server half:
persistence of tokens, encryption at rest, per-user mapping, and revocation.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlencode

import httpx

from minigate import __version__
from minigate.logging import logger

_TIMEOUT_SECONDS = 30.0

__all__ = [
    "ClientRegistration",
    "OAuthError",
    "PkcePair",
    "TokenSet",
    "UpstreamOAuth",
    "discover",
]


class OAuthError(Exception):
    """Raised when an upstream authorization step fails."""


@dataclass(frozen=True)
class PkcePair:
    """A PKCE verifier and its S256 challenge."""

    verifier: str
    challenge: str

    @classmethod
    def generate(cls) -> PkcePair:
        # RFC 7636 allows 43-128 characters; 32 random bytes base64url-encodes to 43.
        verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
        return cls.from_verifier(verifier)

    @classmethod
    def from_verifier(cls, verifier: str) -> PkcePair:
        """Rebuild a pair from a stored verifier.

        The bridge generates its upstream verifier at `/authorize` and needs it again at
        the callback, which is a separate request. Only the verifier is worth storing;
        the challenge is derived.
        """
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return cls(verifier=verifier, challenge=challenge)


@dataclass(frozen=True)
class ClientRegistration:
    """What an authorization server returned when MiniGate registered as a client."""

    client_id: str
    client_secret: str | None = None
    registration_response: dict[str, Any] = field(default_factory=dict)

    @property
    def is_confidential(self) -> bool:
        return bool(self.client_secret)


@dataclass(frozen=True)
class TokenSet:
    """Tokens issued by an upstream authorization server."""

    access_token: str
    token_type: str = "Bearer"
    refresh_token: str | None = None
    expires_in: int | None = None
    scope: str | None = None
    id_token: str | None = None
    extra_fields: tuple[str, ...] = ()
    """Names of any other keys the token response carried. Names only, never values."""

    @property
    def authorization_header(self) -> str:
        """The Authorization header value, with the bearer scheme canonicalised.

        RFC 6749 §7.1 makes `token_type` case-insensitive and RFC 6750 names the scheme
        `Bearer`, so an authorization server may legitimately answer `"bearer"` while a
        resource server accepts only `Bearer`. Linear does exactly that, and sending the
        lowercase form verbatim means the credential is never parsed — the request reads
        as unauthenticated rather than as rejected, which is a materially harder failure
        to diagnose.

        Only the bearer scheme is normalised. Anything else is passed through untouched,
        so an unexpected scheme stays visible instead of being quietly rewritten.
        """
        scheme = "Bearer" if self.token_type.lower() == "bearer" else self.token_type
        return f"{scheme} {self.access_token}"

    def identity(self) -> dict[str, str]:
        """Claims identifying who consented, from the id_token, or empty if there is none.

        The signature is not verified, and that is deliberate rather than an omission:
        OpenID Connect Core §3.1.3.7 permits a client to skip validation when the token
        was received directly from the token endpoint over a TLS-protected channel it
        authenticated, which is exactly this path. There is no third party between the
        authorization server and us who could have substituted it.

        Returned claims are used for audit attribution only. Nothing is authorized on
        the strength of them — authorization is the upstream's job, and it enforces that
        with the access token, not with these.
        """
        if not self.id_token:
            return {}
        parts = self.id_token.split(".")
        if len(parts) != 3:
            return {}
        try:
            padded = parts[1] + "=" * (-len(parts[1]) % 4)
            claims = json.loads(base64.urlsafe_b64decode(padded))
        except (ValueError, json.JSONDecodeError):
            return {}
        if not isinstance(claims, dict):
            return {}
        return {
            key: str(claims[key])
            for key in ("sub", "email", "name", "preferred_username")
            if claims.get(key)
        }

    def describe(self) -> str:
        """A safe summary. Never returns the token itself.

        `token_type` is included because it goes into the Authorization header verbatim:
        a server that returns a scheme the resource server will not parse produces a 401
        that looks exactly like a rejected token, and the distinction is invisible
        without seeing this value.
        """
        shape = "jwt" if self.access_token.count(".") == 2 else "opaque"
        extra = f" extra={list(self.extra_fields)}" if self.extra_fields else ""
        return (
            f"type={self.token_type!r} len={len(self.access_token)} {shape} "
            f"refresh={'yes' if self.refresh_token else 'no'} "
            f"expires_in={self.expires_in} scope={self.scope!r}{extra}"
        )


async def _get_json(client: httpx.AsyncClient, url: str, what: str) -> dict[str, Any]:
    try:
        response = await client.get(url, timeout=_TIMEOUT_SECONDS)
    except httpx.HTTPError as e:
        msg = f"Could not reach {what} at {url}: {e}"
        raise OAuthError(msg) from e
    if response.status_code != 200:
        msg = f"{what} at {url} returned {response.status_code}"
        raise OAuthError(msg)
    try:
        return response.json()
    except ValueError as e:
        msg = f"{what} at {url} was not JSON"
        raise OAuthError(msg) from e


async def discover(
    resource_url: str, client: httpx.AsyncClient | None = None
) -> dict[str, Any]:
    """Read an upstream's protected-resource and authorization-server metadata.

    The resource metadata names its authorization servers; the first is used. Both
    documents are returned so a caller can see exactly what the upstream advertised —
    which is the information the passthrough failure turned on.
    """
    owns_client = client is None
    client = client or httpx.AsyncClient(follow_redirects=True)
    try:
        base = resource_url.rstrip("/")
        parts = httpx.URL(base)
        origin = f"{parts.scheme}://{parts.netloc.decode()}"
        path = parts.path.rstrip("/")

        # RFC 9728 inserts the resource path after the well-known segment.
        prm_url = f"{origin}/.well-known/oauth-protected-resource{path}"
        prm = await _get_json(client, prm_url, "protected-resource metadata")

        issuers = prm.get("authorization_servers") or []
        if not issuers:
            msg = f"{prm_url} advertises no authorization_servers"
            raise OAuthError(msg)
        issuer = str(issuers[0]).rstrip("/")

        as_url = f"{issuer}/.well-known/oauth-authorization-server"
        as_meta = await _get_json(client, as_url, "authorization-server metadata")

        for required in ("authorization_endpoint", "token_endpoint"):
            if not as_meta.get(required):
                msg = f"{as_url} is missing {required}"
                raise OAuthError(msg)

        return {"resource_metadata": prm, "authorization_server": as_meta, "issuer": issuer}
    finally:
        if owns_client:
            await client.aclose()


class UpstreamOAuth:
    """Drives an authorization-code flow against one upstream authorization server.

    Args:
        metadata: The authorization server's metadata document.
        resource: The RFC 8707 resource indicator to request. This must be the
            identifier the *upstream* owns — the whole point of the bridge is that
            MiniGate asks for a resource the upstream will actually mint a token for,
            rather than forwarding a request for its own identifier.
        redirect_uri: Where the authorization server sends the user back.
    """

    def __init__(
        self,
        metadata: dict[str, Any],
        resource: str,
        redirect_uri: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.metadata = metadata
        self.resource = resource
        self.redirect_uri = redirect_uri
        self._client = client or httpx.AsyncClient(follow_redirects=True)
        self._owns_client = client is None

    # ── registration ─────────────────────────────────────────────────

    async def register(self, client_name: str = "MiniGate") -> ClientRegistration:
        """Register MiniGate as a client via RFC 7591 dynamic registration.

        Linear advertises both a registration endpoint and client-ID metadata document
        support. Dynamic registration is used here because it needs no publicly
        reachable document, which keeps the proving step self-contained.
        """
        endpoint = self.metadata.get("registration_endpoint")
        if not endpoint:
            msg = "Authorization server advertises no registration_endpoint"
            raise OAuthError(msg)

        body = {
            "client_name": client_name,
            "redirect_uris": [self.redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "application_type": "native",
            "software_id": "ai.stridemap.minigate",
            "software_version": __version__,
        }
        scopes = self.metadata.get("scopes_supported")
        if isinstance(scopes, list) and scopes:
            body["scope"] = " ".join(str(s) for s in scopes if s not in ("openid", "email"))

        try:
            response = await self._client.post(endpoint, json=body, timeout=_TIMEOUT_SECONDS)
        except httpx.HTTPError as e:
            msg = f"Registration request to {endpoint} failed: {e}"
            raise OAuthError(msg) from e

        if response.status_code not in (200, 201):
            msg = f"Registration failed: {response.status_code} {response.text[:300]}"
            raise OAuthError(msg)

        data = response.json()
        client_id = data.get("client_id")
        if not client_id:
            msg = "Registration response carried no client_id"
            raise OAuthError(msg)

        logger.bind(module="minigate.oauth").info(
            "Registered with {issuer} as client {client_id}",
            issuer=self.metadata.get("issuer", "?"),
            client_id=client_id,
        )
        return ClientRegistration(
            client_id=str(client_id),
            client_secret=data.get("client_secret"),
            registration_response=data,
        )

    # ── authorization ────────────────────────────────────────────────

    def authorize_url(
        self,
        registration: ClientRegistration,
        pkce: PkcePair,
        state: str,
        scope: str | None = None,
    ) -> str:
        """The URL the user opens to consent.

        `resource` is sent on the authorization request as well as the token request:
        RFC 8707 allows both, and an authorization server that binds audience at consent
        time needs it here.
        """
        params = {
            "response_type": "code",
            "client_id": registration.client_id,
            "redirect_uri": self.redirect_uri,
            "state": state,
            "code_challenge": pkce.challenge,
            "code_challenge_method": "S256",
            "resource": self.resource,
        }
        chosen = scope or self._default_scope()
        if chosen:
            params["scope"] = chosen
        return f"{self.metadata['authorization_endpoint']}?{urlencode(params)}"

    def _default_scope(self) -> str:
        """Every scope the server offers that we have a use for.

        The identity scopes are requested when available so the token response carries an
        id_token, which is the only standard way to learn *who* consented. Without it an
        audit trail can say a client was authorized but not which human stood behind it.
        A server that does not offer them simply yields no identity, and attribution
        falls back to the client.
        """
        scopes = self.metadata.get("scopes_supported")
        if not isinstance(scopes, list):
            return ""
        wanted = [str(s) for s in scopes if s in ("read", "write", "openid", "email")]
        return " ".join(wanted)

    async def exchange(
        self, registration: ClientRegistration, code: str, pkce: PkcePair
    ) -> TokenSet:
        """Trade an authorization code for tokens."""
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": registration.client_id,
            "code_verifier": pkce.verifier,
            "resource": self.resource,
        }
        if registration.client_secret:
            data["client_secret"] = registration.client_secret
        return await self._token_request(data, "authorization code exchange")

    async def refresh(self, registration: ClientRegistration, refresh_token: str) -> TokenSet:
        """Exchange a refresh token for a new access token."""
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": registration.client_id,
            "resource": self.resource,
        }
        if registration.client_secret:
            data["client_secret"] = registration.client_secret
        return await self._token_request(data, "refresh")

    async def _token_request(self, data: dict[str, str], what: str) -> TokenSet:
        endpoint = self.metadata["token_endpoint"]
        try:
            response = await self._client.post(endpoint, data=data, timeout=_TIMEOUT_SECONDS)
        except httpx.HTTPError as e:
            msg = f"Token request ({what}) to {endpoint} failed: {e}"
            raise OAuthError(msg) from e

        if response.status_code != 200:
            # The body carries the OAuth error code, which is the diagnostic that
            # matters; it names no credential.
            msg = f"Token request ({what}) returned {response.status_code}: {response.text[:300]}"
            raise OAuthError(msg)

        payload = response.json()
        token = payload.get("access_token")
        if not token:
            msg = f"Token response ({what}) carried no access_token"
            raise OAuthError(msg)

        known = {"access_token", "token_type", "refresh_token", "expires_in", "scope", "id_token"}
        return TokenSet(
            access_token=str(token),
            token_type=str(payload.get("token_type") or "Bearer"),
            refresh_token=payload.get("refresh_token"),
            expires_in=payload.get("expires_in"),
            scope=payload.get("scope"),
            id_token=payload.get("id_token"),
            extra_fields=tuple(sorted(k for k in payload if k not in known)),
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
