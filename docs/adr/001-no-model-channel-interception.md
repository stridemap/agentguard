# ADR-001: Govern at the MCP protocol layer; no TLS interception

- **Status**: Accepted
- **Date**: 2026-08-10
- **Deciders**: Praveen Radjassegarin (Stridemap Labs LLC)
- **Applies to**: MiniGate

## Context

MiniGate governs AI agents at the point of tool execution: allowing, blocking, and
auditing what an agent may do through the MCP servers it is connected to. It must be
**client-agnostic** (Claude Desktop is one use case among many — Cursor, Claude Code,
VS Code, Goose, and internally built agents are equally in scope) and
**framework-agnostic** (it must not require LangGraph/LangChain, which is the coupling
that constrains the existing AgentGuard interceptor).

Competing products in this category advertise a two-channel architecture: a *tool
execution channel* between the agent and its tools, and an *intelligence channel*
between the agent and the LLM, with the second positioned as what makes enforcement
bypass-resistant. Reaching that second channel requires one of:

1. **Cooperative proxy** — the agent is configured to send model traffic to us
   (`base_url` or equivalent). Requires the agent's owner to opt in.
2. **TLS interception (MITM)** — a root CA is installed on the endpoint so model traffic
   can be decrypted without the agent's cooperation. Required for any client that has no
   configurable model endpoint, which includes Claude Desktop.

This ADR decides whether MiniGate pursues either.

## Decision

**MiniGate governs at the MCP protocol layer. It will not ship or require TLS
interception, and will never ask a customer to install a root CA.**

Coverage is delivered in three tiers, in cost order:

| Tier | Mechanism | Reaches |
|------|-----------|---------|
| 1 | MCP gateway (stdio shim, then remote) | Any MCP client, any framework — one implementation |
| 2 | Thin local adapters around tool execution | Framework-native tools that are not MCP |
| 3 | Cooperative opt-in proxy | Agents reachable by neither tier above; the model channel |

Tier 1 is the product. Tier 2 is built per-framework on demand, modelled on the existing
`govern_tool_call()` wrapper in `agentguard/sdk_adapters.py`, with the LangChain
interceptor demoted to one instance of it rather than the primary path. **Tier 3 is
permitted but deferred** — it is not part of the core architecture and is justified only
by a design partner whose agent no cheaper tier can reach.

Where a customer requires visibility into decrypted model traffic and already operates a
TLS-inspecting proxy (Zscaler, Netskope, Palo Alto), MiniGate integrates with that feed
rather than building a second interception layer.

## Rationale

### Why the protocol layer

MCP is already the framework-agnostic boundary. A single protocol implementation governs
every MCP-speaking client regardless of what it is built with, which is precisely the
requirement that the SDK-callback approach cannot satisfy. Enforcement points are
`tools/list` (filter — the *allow* half), `tools/call` request (block — the *deny* half),
and `tools/call` response (DLP and injection scanning before untrusted content re-enters
context).

### Why not TLS interception

Three reasons, all independent of deployment convenience:

**It is a data-plane business.** Production-quality interception means CA lifecycle and
rotation, selective decryption policy, per-runtime trust configuration across macOS,
Windows, and Linux and across the Node, Python, Go, and Java trust stores, key material
protection, throughput under load, and the audit and penetration-test evidence a customer
will demand before permitting decryption. That is a company, not a component.

**Incumbents own that layer.** Zscaler, Netskope, and Palo Alto have the data plane
deployed and the certificates already trusted. AI traffic inspection is an increment on
infrastructure they have spent a decade building. Competing there means winning at their
strength rather than ours.

**Plaintext custody is unbounded liability.** Interception makes MiniGate the holder of
model conversations and provider API keys for every customer. For a security vendor, a
single incident there is terminal. This risk does not scale down with careful engineering.

Two arguments commonly raised against interception were considered and judged **not**
load-bearing, and are recorded here so they are not re-used:

- *Certificate pinning* — most desktop AI clients use the OS trust store and do not pin.
  The real cost is per-runtime trust configuration, which is an ops burden, not a blocker.
- *Over-broad decryption* — selective decryption by SNI confines inspection to model API
  endpoints. This is standard practice and largely answers the scope objection.

### Why the cooperative proxy is deferred rather than rejected

A cooperative proxy is materially different from interception: no CA, no machine-wide
scope, and per-agent consent from the owner. Its costs are real but bounded — per-provider
wire-format adapters (Anthropic Messages, OpenAI Chat Completions and Responses),
enforcement over streamed responses, and added latency on the model path — and they are
worth paying only against demonstrated demand.

## Consequences

**Accepted benefits**

- No API key custody, no root certificate, no network changes. This is a deployment story
  a small organisation can say yes to, and a differentiator against network-deployed
  competitors.
- Framework and client agnosticism by construction rather than by per-framework effort.
- Sensitive data is caught at the tool boundary — upstream of where a model-channel proxy
  would see it — because it enters agent context through `tools/call` results.

**Accepted costs**

- No visibility into the model channel of agents that do not use MCP. An agent that reads
  data through a governed tool and then discloses it directly to the user is observed at
  the tool boundary but not at the point of disclosure. This is a reporting gap, not an
  enforcement gap.
- Agents using neither MCP nor a local adapter are not governed at all until tier 3 exists.
- "Zero-bypass" cannot be claimed on the strength of dual-channel coverage. Bypass
  resistance must come from remote gateway deployment, tool-definition pinning, discovery,
  and egress policy instead.
- Shadow-AI discovery must be built without decryption: IdP OAuth grant logs (Google
  Workspace, Okta) enumerate authorised remote MCP servers, and endpoint connection
  telemetry (SNI, destination, originating process) identifies model API usage. Together
  these cover most of the discovery requirement at a small fraction of the cost.

## Alternatives considered

**TLS interception as the primary architecture.** Rejected for the three reasons above.

**Cooperative proxy as a core channel rather than an optional module.** Rejected: it does
not reach the clients that most need governance (no configurable endpoint), and it imposes
a permanent per-provider maintenance burden for coverage that tier 1 already provides for
MCP-connected agents.

**Per-framework SDK adapters as the primary integration path.** Rejected as the *primary*
path — it is the AgentGuard model and requires adoption at build time by every framework
in use. Retained as tier 2 for tools that are not exposed over MCP.

## Implementation notes

A framework-neutral event schema is a prerequisite for all three tiers. The current
`AgentEvent` in `agentguard/models.py` requires `run_id` as a UUID and carries
`parent_run_id`, encoding LangChain's execution model into the core type; every
non-LangChain adapter would have to fabricate values to satisfy it. Define an event keyed
on server, session, method, tool, and direction, and map the LangChain interceptor *into*
it. The policy schema should likewise name `server`, `tool`, `method`, and `direction`
rather than anything presupposing a callback graph.

## Revisit triggers

Reopen this decision if any of the following becomes true:

- A design partner requires model-channel governance on an agent reachable by no other
  tier, has no existing inspection proxy, and will fund it. Build **tier 3 first**, not
  interception.
- Stridemap Labs is resourced to staff a data-plane team and elects to compete directly in
  network inspection.
- MCP adoption stalls such that tier 1 no longer covers a majority of governed agents.
