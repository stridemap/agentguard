# ADR-002: OAuth passthrough, not a gateway-owned authorization server

- **Status**: Accepted
- **Date**: 2026-08-12
- **Deciders**: Praveen Radjassegarin (Stridemap Labs LLC)
- **Applies to**: MiniGate remote gateway mode

## Context

Remote gateway mode makes MiniGate an MCP server that clients connect to over HTTPS,
proxying to the vendor's real endpoint. MCP servers are OAuth 2.1 protected resources, so
the gateway has to participate in authorization. Three options:

1. **Gateway as authorization server.** MiniGate implements OAuth itself — dynamic client
   registration, authorization and token endpoints, JWKS, refresh — issues its own tokens
   to clients, and separately holds a grant against each upstream.
2. **Passthrough.** MiniGate advertises the *upstream's* authorization server in its
   protected-resource metadata. The client obtains a token from that server directly and
   MiniGate relays the `Authorization` header verbatim.
3. **Token exchange.** MiniGate accepts a token bound to itself and exchanges it for an
   upstream token via RFC 8693.

## Decision

**Passthrough.** MiniGate advertises the upstream's issuer, relays the client's bearer
token unchanged, and never mints, stores, or refreshes a token.

`GET /.well-known/oauth-protected-resource/mcp/{server}` returns the upstream's
`authorization_servers`; an unauthenticated request gets `401` with a `WWW-Authenticate`
header pointing back at that metadata. `auth.mode: none` disables the requirement for
local and development use.

## Rationale

**It keeps the credential-custody constraint from ADR-001 intact.** That decision rejected
TLS interception partly because it would make MiniGate the holder of provider credentials
for every customer. Becoming an authorization server reintroduces exactly that liability
through a different door: a token database is a breach target, and for a security vendor
one incident there is terminal. Passthrough means a compromise of the gateway yields
in-flight requests, not a durable credential store.

**It is a fraction of the work.** Option 1 is DCR, PKCE, token lifecycle, key rotation,
and revocation — a component with its own security review, on a solo team. Option 3 needs
upstreams that implement RFC 8693, which vendor MCP servers generally do not.

**It fails safe.** MiniGate cannot grant access the user has not already been granted,
because it never issues anything. The worst it can do is refuse.

## Consequences

**Accepted benefits**

- No token storage, refresh, or rotation, and no key material at rest.
- Revocation stays where it belongs: the user revokes at the vendor and the gateway loses
  access immediately, with nothing to invalidate here.
- Scopes and consent screens remain the vendor's, which is what the user recognises.

**Accepted costs**

- **Audience binding is the sharp edge.** Under RFC 8707 a client requests a token for a
  specific resource. If it uses MiniGate's URI, a strict upstream may reject the relayed
  token as having the wrong audience. Mitigation is to set `http.public_url` to the
  upstream's canonical resource identifier so the token is bound to what will actually
  validate it. This works with upstreams that do not tie the resource identifier to the
  request host, and fails with those that do — in which case that upstream cannot be
  fronted in passthrough mode.
- MiniGate cannot enforce its own scopes or issue narrower tokens than the upstream did.
- Per-user attribution comes from whatever the upstream token carries; the gateway adds
  no identity of its own.

## Operational note — added 2026-08-13 after testing against live vendor servers

Probing Linear, Notion, and Todoist showed that **which side issues the 401 decides whether
the audience problem arises at all**, and the better answer is not the one this ADR originally
gave.

With `auth.require: false`, MiniGate forwards an unauthenticated request, the upstream answers
`401`, and MiniGate relays that challenge verbatim — including
`WWW-Authenticate: … resource_metadata="https://mcp.linear.app/.well-known/…"`. The client then
authenticates against the **upstream's** resource identifier, so the token it receives is
audience-bound to the upstream and is accepted when relayed. The mismatch never occurs.

With `auth.require: true`, MiniGate issues its own challenge pointing at its own metadata,
whose `resource` is the gateway URL. The client binds the token to MiniGate — which is exactly
the RFC 8707 mismatch described above.

**Guidance:** when fronting an upstream that already implements OAuth, prefer
`auth.require: false` and let the upstream challenge. Reserve `require: true` for upstreams
with no authorization of their own, or where rejecting unauthenticated traffic before it costs
an upstream round trip is worth the audience risk. This does not change the decision — it is
still passthrough, and MiniGate still stores nothing — it changes which knob delivers it
cleanly.

## Alternatives considered

**Gateway as authorization server.** Rejected: reintroduces credential custody, and is a
component-sized build with a security surface of its own. Revisit only if a design partner
needs gateway-enforced scopes or per-user policy that the upstream token cannot express.

**Token exchange (RFC 8693).** Rejected for now: correct in principle, unsupported by the
upstreams that matter. Reconsider if vendor MCP servers adopt it.

## Revisit triggers

- An upstream MiniGate must front rejects relayed tokens on audience grounds and cannot be
  configured around it.
- A customer requires policy keyed to an identity the upstream token does not carry.
- Vendor MCP servers broadly implement RFC 8693 token exchange.
