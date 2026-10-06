# MiniGate

An MCP protocol gateway that governs what AI agents may do — by [Stridemap Labs LLC](https://stridemap.ai).

MiniGate sits between an MCP client and the MCP servers it connects to. It filters
the tool list the model is allowed to see, blocks disallowed calls before they reach
an external system, scans results before they re-enter model context, and records
every decision to a tamper-evident audit chain.

Governance happens at the protocol layer, so it is client- and framework-agnostic:
Claude Desktop, Cursor, Claude Code, VS Code, Goose, or any agent built on an MCP
client library, whatever framework it uses. No SDK adoption, no code change in the
agent, no API keys, no TLS interception. See
[ADR-001](../docs/adr/001-no-model-channel-interception.md).

## Status

Every MCP surface is governed in both directions — tools, resources, prompts, and the two
server-initiated methods — with definition pinning and data lineage. Two transports: a
stdio shim for desktop clients, and a remote HTTP gateway with OAuth passthrough for
claude.ai web and centrally administered deployments.

## Quick start

```bash
pip install -e ".[dev]"
cp minigate.example.yaml minigate.yaml
minigate snippet --server-name notion --config minigate.yaml
```

Paste the printed fragment into `claude_desktop_config.json`
(`~/Library/Application Support/Claude/` on macOS) and restart the client:

```json
{
  "mcpServers": {
    "notion": {
      "command": "minigate",
      "args": ["stdio", "--server-name", "notion", "--config", "minigate.yaml"]
    }
  }
}
```

Then remove the directory version of the same connector, or calls will route around
the gateway.

```bash
minigate verify --database minigate.db    # confirm the audit chain is intact
```

## Remote gateway

For claude.ai on the web, or any deployment where you cannot configure each endpoint, run
MiniGate as a remote MCP server that clients connect to instead of the vendor's:

```yaml
http:
  host: 127.0.0.1
  port: 8787
  public_url: https://minigate.example.com   # what clients actually dial
  auth:
    mode: passthrough      # passthrough | none
    require: true

servers:
  notion:
    url: https://mcp.notion.com/mcp
    authorization_servers: ["https://mcp.notion.com"]
    scopes: ["mcp:read"]
```

```bash
minigate serve --config minigate.yaml
```

Clients then point at `https://minigate.example.com/mcp/notion`. Every control is the same
one the stdio shim applies — the decision layer has no I/O, so both transports share it
verbatim.

**OAuth is passthrough.** MiniGate advertises the *upstream's* authorization server at
`/.well-known/oauth-protected-resource/mcp/{server}` and relays the client's bearer token
unchanged. It mints, stores, and refreshes nothing, so there is no token database to
breach and revocation stays with the vendor. The trade-off — token audience binding under
RFC 8707 — is recorded in [ADR-002](../docs/adr/002-oauth-passthrough.md).

Streaming responses are governed event by event as they pass, not buffered, so the first
token still reaches the client promptly.

Not yet: the optional `GET /mcp/{server}` server-to-client stream (returns 405), and SSE
session resumption.

## How enforcement works

| Point | Direction | Action |
|-------|-----------|--------|
| `tools/list` | server → client | Blocked tools are stripped before the model sees them |
| `tools/list` | server → client | Definitions are checked against the approved registry |
| `tools/list` | server → client | Tool descriptions are scanned for hidden instructions |
| `tools/call` | client → server | Blocked calls are answered by MiniGate, never forwarded |
| `tools/call` | server → client | Results are DLP- and injection-scanned before entering context |
| `tools/call` | both | Data lineage — values tainted on the way in, checked on the way out |
| `resources/list` | server → client | Blocked resources stripped; metadata scanned for instructions |
| `resources/read` | client → server | Policy evaluation on the URI, before anything is read |
| `resources/read` | server → client | Content DLP- and injection-scanned, and tainted for lineage |
| `prompts/list` | server → client | Blocked prompts stripped; descriptions and argument descriptions scanned |
| `prompts/get` | both | Policy on the prompt, DLP on arguments, message scanning on the way back |
| `sampling/createMessage` | **server → client** | Policy, includeContext ceiling, injection scan of the server's prompt |
| `sampling` reply | client → server | Completion DLP-scanned and lineage-checked before it leaves |
| `elicitation/create` | **server → client** | Policy, sensitive-field refusal, injection scan of the message |
| `elicitation` reply | client → server | What the user typed is DLP-scanned and lineage-checked |

Both `tools/*` points are needed. Filtering alone is bypassable — nothing stops a
client calling a tool that was never listed. Blocking alone wastes context and lets
the model plan around tools it can never use.

A blocked call is answered with a JSON-RPC **result** carrying `isError: true`, not
a protocol-level error. A protocol error reads as a transport failure and the client
may retry; an error result lands in model context, so the agent can explain the block
to the user and choose another approach.

## Tool registry (definition pinning)

A `tool_name` rule cannot see a rug-pull: a tool passes review, then the server
changes its description or input schema. The name is unchanged, so name-based policy
still says ALLOW — while the model is now reading different instructions and handing
over different data.

The registry pins the full definition at approval time and re-hashes it on every
`tools/list`:

```bash
minigate registry sync --server-name notion --config minigate.yaml --approved-by you
minigate registry list --config minigate.yaml
minigate registry diff --server-name notion --config minigate.yaml   # exit 1 if review needed
```

`sync` reads the server's manifest and approves it — it never calls a tool, so
pointing it at an unfamiliar server is safe. `diff` exits non-zero when anything is
new or changed, so it works as a CI check.

| Verdict | Meaning |
|---------|---------|
| `APPROVED` | Hash matches what was reviewed |
| `CHANGED` | The server is advertising something else under an approved name |
| `UNKNOWN` | Never reviewed |
| `UNVERIFIED` | Called without this session having seen it advertised |

In `enforce` mode anything not `APPROVED` is withheld from `tools/list` and blocked on
call. Enable in `observe` first — it reports without withholding, so you can populate
the registry against a working setup. An empty registry in `enforce` mode denies
everything; that is the right direction for an allowlist, and why it is not the default.

The whole tool object is hashed, not a chosen subset: any server-controlled field can
carry instructions, so a benign-looking addition still warrants re-approval.

**A definition can only be verified where the server advertises it.** A call for a tool
this session never saw listed is `UNVERIFIED`, not `APPROVED` — matching an approved
*name* is exactly the check a rug-pull defeats. Every MCP client lists tools at session
start, so this costs nothing in practice.

## Resources

Resources are the other way data enters model context — files, pages, documents — so they
get the same treatment as tools, addressed by URI instead of by name:

```yaml
- id: MG-030
  name: Block credential and key material
  priority: 15
  conditions:
    tool_name: ".*\\.resource:.*(/\\.ssh/|/\\.aws/|id_rsa|\\.pem|credentials).*"
  action: BLOCK
```

Blocked resources are stripped from `resources/list`, and a read of one is answered by
MiniGate without reaching the server. Resource names and descriptions are scanned for
hidden instructions, because they are model-visible text the server controls — the same
poisoning surface as a tool description, and the resource never has to be read for the
attack to land. Content is DLP- and injection-scanned on the way back, and tainted for
lineage.

`resources/subscribe` is gated by the same rules as `resources/read` — a subscription is a
standing read.

Two deliberate differences from tools. Resources are **allowed by default** once the
secret-path rules have run, because enumerating every legitimate URI in advance is
impractical; delete `MG-110` from the shipped policy to make them an allowlist too.
Resource **templates are not policy-filtered**, since `file:///{path}` describes a shape
rather than a resource — the concrete read is where policy bites.

## Prompts

A prompt's messages are inserted into the conversation as **authored turns**, not as data
the model reads — a strictly stronger trust position than a tool result, and the sharpest
surface in the protocol. Injected content there is replaced outright rather than redacted.

Prompts are addressed as `<server>.prompt:<name>`, their own namespace slot. That matters
more than it looks: `prompts/get` and `tools/call` both carry the target in `params.name`,
so without separate namespaces a rule written for a tool would silently govern a prompt of
the same name.

MiniGate scans a prompt's description **and each argument's description** at list time —
both are model-visible and server-controlled, and a field description telling the model
what to put in it is a natural place to hide an instruction. On the way back it scans the
expanded messages, including text nested inside embedded resources.

Prompts are allowed by default (`MG-120`), because they are user-initiated and few, and
blocking by name is rarely the control you want. Delete that rule to make them an
allowlist.

## Server-initiated sampling

Everything else flows client-to-server. `sampling/createMessage` runs the other way: the
server asks *your* client to run an LLM. It authors the prompt, spends your tokens, and
receives the completion — so a server that can sample can both instruct the model and read
what it produced.

The shipped policy denies it outright (`MG-050`). To enable it for one server, replace that
rule with a scoped ALLOW and keep the context ceiling low:

```yaml
sampling:
  max_include_context: thisServer   # none | thisServer | allServers
  scan_completions: true
```

`includeContext: allServers` asks the client to attach context from **every** connected
server and hand the result to the one that asked — a cross-server egress channel that
`thisServer` does not open. An unrecognised value is rejected rather than waved through.

Rejection is a JSON-RPC error, not an error-carrying result: the requester is a server
following the protocol, not a model reading context. The client never sees a rejected
request.

The reply is governed too. A completion is model output travelling to the server, so DLP
redacts it and lineage checks whether it carries anything from a more trusted source.

## Elicitation

`elicitation/create` is the only MCP channel that reaches the **user** directly. The server
writes the words a human reads and gets back whatever they type, so the threat is social
engineering rather than injection — a form headed "your session expired, confirm your
identity" that asks for a password harvests it straight from the person.

The MCP spec says servers MUST NOT use elicitation to request sensitive information.
MiniGate enforces that rather than trusting it:

```yaml
elicitation:
  scan_responses: true
  sensitive_fields:        # defaults cover passwords, keys, tokens, SSNs, cards, OTP/MFA
    - "pass(word|wd|phrase)"
    - "api[-_ ]?key"
    - "\\botp\\b"
```

The check reads the whole form, not just field names. A field called `value` with the title
"Your API key" asks for the same thing, and a generic field paired with a message saying
"paste your MFA code" is the same attack again — so names, titles, descriptions, enum
options, and the message text all go through one pass.

Elicitation is allowed by policy (`MG-130`) because it is a legitimate feature: a server
asking which repository to use is ordinary. That layering is deliberate — policy permits
the channel, the sensitive-field check refuses the abuse of it. A refused form is never
rendered, so no one is ever shown it.

What the user types is governed too: DLP redacts it and lineage checks it before it reaches
the server. `decline` and `cancel` carry no content and pass through untouched.

## Data lineage

Some breaches are a sequence, not a call. An agent bulk-reads customer records, then files
them into a public ticket — each call individually permitted, no per-call rule violated.

MiniGate taints the values a tool returns with the trust level of the server that produced
them, and checks later calls' arguments against those marks. Data may flow to equal or
higher trust, never downward.

```yaml
lineage:
  enabled: true
  mode: enforce           # off | observe | enforce
  store: minigate-taint.db
  ttl_seconds: 3600

servers:
  crm:
    trust: restricted     # PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED
  linear:
    trust: internal
    tool_trust:
      create_public_issue: public
```

**Only hashes are stored.** A taint store holding raw customer records would be a worse
liability than the leak it prevents, so values are normalised and SHA-256 hashed on the way
in and compared the same way on the way out.

**The store is shared across processes.** Each MiniGate process fronts one server, so a
process-local store would only see same-server flows — and the case worth catching is
read-from-one, write-to-another. Point every server's config at the same `store` path.

Every server defaults to `INTERNAL`, so an unconfigured deployment detects nothing. That is
deliberate: the tracker should stay quiet until someone has said what is sensitive. Start in
`observe` to see what would fire.

Matching is exact on extracted values, so lineage catches copy-through — the bulk
exfiltration shape — not a model that deliberately paraphrases to evade it.

## Policy

Rules live in YAML and are evaluated by AgentGuard's policy engine. Tools are named
`<server>.<tool>`, where `<server>` is the `--server-name` MiniGate was started with;
non-tool methods are addressed as `<server>.<method>`. Matching is exact-or-regex.

```yaml
rules:
  - id: MG-020
    name: Notion is read-only
    priority: 20
    conditions:
      tool_name: "notion\\.notion-(create|update|move|duplicate)-.*"
    action: BLOCK

  - id: MG-999
    name: Deny anything not explicitly allowed
    priority: 999
    action: BLOCK
```

The engine defaults to ALLOW when no rule matches, so a catch-all deny is what makes
a policy an allowlist. Delete `MG-999` from [policies/minigate.yaml](../policies/minigate.yaml)
to run in monitor-only mode while you learn which tools your agents actually use.

## Failure behaviour

Fail-open on MiniGate's own faults, fail-closed on policy. If the policy engine or a
scanner throws, the call is forwarded and a warning is logged — a broken guardrail
must not break the agent. A rule that evaluates to BLOCK always blocks. Set
`fail_closed: true` to invert the first half; the second is not configurable.

## Limitations

- **Governance, not containment.** Anyone who can edit `claude_desktop_config.json`
  can point it back at the raw server. MiniGate is enforcement for cooperative users
  plus tamper-evident audit. Real containment needs MDM-managed config, org connector
  allowlists, or network egress control.
- **stdio only.** Remote MCP servers must be bridged with `mcp-remote`. Native remote
  gateway mode is phase 3.
- **Anthropic-hosted connectors cannot be interposed.** Gmail, Google Calendar, and
  Google Drive run in Anthropic's cloud with no endpoint to redirect. Disable them, or
  replace them with your own MCP server behind MiniGate.
- **Lineage matches exact values.** Paraphrased or summarised data is not matched, and
  trust levels must be declared before anything is detected.
- **Binary resource content is not scanned.** Base64 `blob` parts are tainted for lineage
  but cannot be meaningfully DLP- or injection-scanned.

## Development

```bash
pytest tests/minigate/ -q
ruff check minigate/ tests/minigate/
```

`MINIGATE_LOG_LEVEL` controls verbosity. All logs go to stderr; stdout carries the
MCP protocol and must never be written to directly.
