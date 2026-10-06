# Claude custom connector → MiniGate → Linear: authorization fails

**Date:** 3 September 2026
**Gateway:** `https://minigate-production.up.railway.app/mcp/linear`
**Upstream:** `https://mcp.linear.app/mcp`
**Anthropic references:** `ofid_ce95b31fb4fcfe55`, `ofid_0ce693e059d107ba`,
`ofid_6435b02857667b5f`, `ofid_68eaf18476b4af31`, `ofid_2019056ec157bc2b`

## Summary

A Claude Desktop **custom connector** pointed at an HTTP MCP gateway that proxies Linear
completes OAuth — the Linear consent screen appears and is approved — and then every
subsequent MCP call is rejected by Linear with `invalid_token`.

The **same gateway, same upstream, same token shape** works when driven by `curl` or by
`mcp-remote`. Only the connector path fails.

## What the client shows

Browser tab during the flow:

> Couldn't connect. Taking you back to the desktop app. You can close this tab.

Then in the app:

> Authorization with MiniGate — Linear failed. You can check your credentials and
> permissions.

## What the gateway observes

```
22:43:23  POST /mcp/linear                                    -> 401  auth=no   python-httpx
22:43:23  GET  /.well-known/oauth-protected-resource/mcp/linear -> 200  auth=no   python-httpx
22:43:23  GET  /.well-known/oauth-protected-resource           -> 404  auth=no   python-httpx
22:43:23  GET  /.well-known/oauth-authorization-server         -> 404  auth=no   python-httpx
          ... user approves Linear consent ...
22:43:37  POST /mcp/linear                                    -> 401  auth=yes  Claude-User
22:43:37  POST /mcp/linear                                    -> 401  auth=yes  Claude-User
          ... ~20 more over 18 seconds, then the client gives up ...
```

Linear's refusal, logged verbatim from the upstream response:

```
Upstream refused: 401 www-authenticate='Bearer realm="OAuth",
  resource_metadata="https://mcp.linear.app/.well-known/oauth-protected-resource/mcp",
  error="invalid_token", error_description="Missing or invalid access token"'
```

Token shape presented by the client (length and format only; never logged in full):

```
Token shape: len=86 opaque
```

That is structurally identical to a token `mcp-remote` obtains and which **succeeds**
through the same gateway.

## What has been ruled out

| Hypothesis | Evidence against |
|---|---|
| Gateway relay is broken | A valid Linear token returns **HTTP 200** through the gateway with a correctly filtered tool list. Verified repeatedly. |
| `Authorization` header not forwarded | Upstream receives it verbatim; `_relay_response_headers` skips only hop-by-hop headers. |
| Discovery document wrong | Ours is byte-identical to Linear's: same `resource`, `authorization_servers`, `scopes_supported`, `bearer_methods_supported`. |
| Discovery not re-fetched / cached | Client fetched it at 22:43:23, after the fix, and got the corrected document. |
| Empty `scopes_supported` | Was a real bug, fixed. Now `["read","write"]`, matching Linear. Failure persists. |
| Resource identifier mismatch (RFC 8707) | Fixed with a per-server `resource_identifier`; the gateway now advertises `https://mcp.linear.app/mcp`, Linear's own. Failure persists. |
| `auth.require` challenge origin | Tried both. With `require: false` the upstream issues the 401 and it is relayed intact. Failure persists. |
| Wrong grant type / JWT / id-jag | Token is `len=86 opaque`, same shape as the working one. |
| OAuth client registration method | Tried both CIMD and DCR. Linear advertises `client_id_metadata_document_supported: true` and a `registration_endpoint`. Failure persists. |
| GET SSE stream requirement | Gateway returns 405 there, but the client never reached that stage — it fails on POST. |

## Reproduction

Works:

```bash
curl -X POST https://minigate-production.up.railway.app/mcp/linear \
  -H "Authorization: Bearer <token from mcp-remote>" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# -> 200, governed tool list (36 of Linear's 57 tools)
```

Fails: add the same URL as a Claude Desktop custom connector.

## Notes that may matter

- A custom connector pointing **directly** at `https://mcp.linear.app/mcp` cannot be
  added for comparison: *"A connector with this URL already exists in your organization"*
  — the stock Linear connector owns it. So directory-connector vs custom-connector against
  the identical endpoint could not be tested.
- The same gateway fronting **Google Drive** (`drivemcp.googleapis.com/mcp/v1`) fails at an
  earlier stage with *"Couldn't **register** with … sign-in service"*, because Google does
  not support dynamic client registration. That is expected and unrelated, but it shows
  Linear gets materially further: registration succeeds, consent succeeds, the token is
  minted, and only then is it refused.
- The unresolved difference lives inside an opaque token: which audience it was bound to,
  or which OAuth client it was issued to. Neither is observable from the resource server.

## The shape of the question

This is a custom connector whose **authorization server belongs to a third party**
(Linear) rather than to the connector's own host. That is an unusual topology and may be
the crux — either the `resource` parameter Claude sends at the token endpoint, or a
restriction on which OAuth clients Linear will honour for its MCP resource.

---

## Resolution path — 6 October 2026

**Status: the passthrough approach is abandoned. A bridge replaces it.**

Two discovery documents, fetched live, explain why no configuration of a passthrough
gateway completes this flow:

```
ours  → "resource": "https://minigate-production.up.railway.app/mcp/linear"
Linear→ "resource": "https://mcp.linear.app/mcp"     (in its AS metadata)
```

Three requirements that cannot all hold at once:

1. **RFC 9728** obliges a resource server to advertise its *own* identifier, and a
   compliant client rejects metadata where it does not match. MiniGate therefore cannot
   advertise Linear's URI — which is why the `resource_identifier` override was not a
   fix and is no longer set.
2. **Claude propagates it** as the RFC 8707 `resource` on authorization and token
   requests.
3. **Linear's AS serves exactly one resource** and will not mint a usable token for one
   it does not own.

No Claude client currently supports overriding or omitting the resource parameter
(anthropics/claude-code#73460, #98818), so waiting is not a plan.

### Step 1 — upstream leg proven

`minigate oauth-probe --resource-url https://mcp.linear.app/mcp`

With MiniGate registering as a client in its own right and requesting Linear's own
resource identifier:

```
register   → client_id UaquYlRkpEkJHg91 (public, DCR)
token      → type='bearer' len=86 opaque refresh=yes expires_in=86100
             scope='read write' extra=['resource']
tools/list → HTTP 200, 68 tools
```

**This does not isolate the cause of the connector failure.** It differs from that path
in both the resource requested and the client identity. It establishes only that the
bridge's upstream leg works — which is sufficient, because the bridge replaces both.

### Two implementation defects found on the way, worth recording

- **Linear answers `token_type: "bearer"`; its resource server accepts only `Bearer`.**
  Sent verbatim the credential is never parsed, and the 401 carries no `error=` code —
  indistinguishable from a rejected token without a positive control. RFC 6749 §7.1
  makes `token_type` case-insensitive, so the scheme is now canonicalised on the wire
  while the observed value is still reported for diagnosis.

- **Linear's 401 challenge is not stable over time.** The same bogus token produced a
  challenge with `error=invalid_token` and, minutes later, one without. The presence of
  `error=` is a reliable discriminator only within a back-to-back comparison, never
  across runs. Two wrong diagnoses were built on it before this was noticed.

### Also observed

Linear now advertises **68 tools**, up from 57 in September. `minigate registry diff`
will report the new ones, and in `enforce` mode they are withheld until approved.

### Next

Steps 2–5: authorization-server surface, token storage, caller validation, then
multi-tenancy. See the bridge design note.
