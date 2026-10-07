"""MiniGate gateway configuration.

A single YAML file describes which upstream MCP servers MiniGate fronts, which
policy governs them, and how the guardrails are tuned:

    client_id: claude-desktop
    policy: policies/minigate.yaml
    database_url: minigate.db
    fail_closed: false

    dlp:
      enabled: true
      sensitivity: MEDIUM

    injection:
      enabled: true
      sensitivity: LOW        # stage-1 regex only; stage 2 is an LLM call
      block_on_injected: true

    servers:
      notion:
        command: ["npx", "-y", "mcp-remote", "https://mcp.notion.com/mcp"]
      filesystem:
        command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        policy: policies/filesystem.yaml   # optional per-server override
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator


class DLPSettings(BaseModel):
    """PII scanning configuration."""
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    enabled: bool = Field(default=True)
    sensitivity: str = Field(default="MEDIUM", description="LOW | MEDIUM | HIGH")
    redact_requests: bool = Field(
        default=True, description="Redact detected PII from tool arguments before forwarding"
    )
    redact_responses: bool = Field(
        default=True, description="Redact detected PII from tool results before they enter context"
    )


class InjectionSettings(BaseModel):
    """Prompt-injection detection configuration.

    Sensitivity LOW runs stage-1 regex only. MEDIUM and HIGH invoke the stage-2 LLM
    classifier, which is far too slow to sit inline on a tool call — leave this at
    LOW unless you have measured the latency you are accepting.
    """
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    enabled: bool = Field(default=True)
    sensitivity: str = Field(default="LOW", description="LOW | MEDIUM | HIGH")
    block_on_injected: bool = Field(
        default=True, description="Replace tool results whose content scores INJECTED"
    )
    scan_tool_descriptions: bool = Field(
        default=True, description="Scan tool descriptions on tools/list (tool poisoning)"
    )


class RegistrySettings(BaseModel):
    """Approved-tool registry with definition pinning.

    Defaults to observe rather than enforce: turning pinning on should surface what
    would be blocked, not silently remove every tool from a working setup. Populate
    with `minigate registry sync`, review the diff, then switch to enforce.
    """
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    enabled: bool = Field(default=False)
    path: str = Field(default="minigate-registry.yaml")
    mode: str = Field(default="observe", description="off | observe | enforce")


class LineageSettings(BaseModel):
    """Trust-boundary tracking across chained tool calls.

    The taint store is shared across MiniGate processes on purpose: each process fronts
    one server, so an in-process store could only see same-server flows — and the case
    worth catching is read-from-one, write-to-another.
    """
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    enabled: bool = Field(default=False)
    mode: str = Field(default="observe", description="off | observe | enforce")
    store: str = Field(default="minigate-taint.db", description="Shared taint store path")
    ttl_seconds: float = Field(
        default=3600.0, description="How long a value stays tainted after it is read"
    )
    min_value_length: int = Field(
        default=8, description="Values shorter than this are ignored — they match everything"
    )
    max_values_per_result: int = Field(
        default=200, description="Cap on values tainted from one tool result"
    )


class SamplingSettings(BaseModel):
    """Controls on `sampling/createMessage` — a server asking the client to run an LLM.

    The direction is what makes this dangerous: the server authors the prompt, spends the
    user's tokens, and receives the completion. `includeContext` is the sharpest part,
    because `allServers` asks the client to attach context from every connected server and
    hand the result to this one.
    """
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    max_include_context: str = Field(
        default="thisServer",
        description="Highest includeContext a server may request: none | thisServer | allServers",
    )
    scan_completions: bool = Field(
        default=True,
        description="DLP-scan and lineage-check the completion before it returns to the server",
    )


class ElicitationSettings(BaseModel):
    """Controls on `elicitation/create` — a server asking the client to prompt the user.

    This is the only MCP channel that reaches the human directly, with the server writing
    the words they read. The risk is therefore social engineering rather than injection:
    a form that says "confirm your identity" and asks for a password harvests it straight
    from the user. The MCP spec says servers MUST NOT request sensitive information;
    these settings are how the client enforces that rather than trusting it.
    """
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    sensitive_fields: list[str] = Field(
        default_factory=lambda: [
            r"pass(word|wd|phrase)",
            r"secret",
            r"api[-_ ]?key",
            r"access[-_ ]?token",
            r"auth[-_ ]?(code|token)",
            r"credential",
            r"private[-_ ]?key",
            r"seed[-_ ]?phrase",
            r"mnemonic",
            r"ssn",
            r"social[-_ ]?security",
            r"credit[-_ ]?card",
            r"card[-_ ]?number",
            r"cvv|cvc",
            r"\bpin\b",
            r"\botp\b",
            r"\bmfa\b|\b2fa\b",
        ],
        description="Patterns that must not appear in a requested field name or in the message",
    )
    scan_responses: bool = Field(
        default=True,
        description="DLP-scan and lineage-check what the user typed before it reaches the server",
    )


class AuthSettings(BaseModel):
    """How the HTTP gateway authenticates clients.

    `passthrough` is the default and the reason MiniGate stays out of the credential
    business: the client obtains a token from the upstream's own authorization server and
    MiniGate relays it verbatim. No token is minted, stored, or refreshed here — the same
    principle as ADR-001, applied to OAuth.
    """
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    mode: str = Field(
        default="passthrough", description="passthrough | bridge | none"
    )
    """`bridge` makes MiniGate its own authorization server, exchanging the token it
    issued for the upstream credential it maps to. That is the only mode that works when
    the upstream's authorization server serves a resource MiniGate cannot advertise —
    and it means MiniGate holds credentials, reversing ADR-002 deliberately."""
    require: bool = Field(
        default=True, description="Reject unauthenticated requests with 401 + WWW-Authenticate"
    )


class HttpSettings(BaseModel):
    """Remote gateway mode — MiniGate as an MCP server over Streamable HTTP."""
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8787)
    public_url: str | None = Field(
        default=None,
        description="Externally reachable base URL, used as the OAuth resource identifier. "
        "Required behind a proxy or TLS terminator, where the request host is not what "
        "the client actually dialled.",
    )
    upstream_timeout_seconds: float = Field(default=120.0)
    auth: AuthSettings = Field(default_factory=AuthSettings)


class ServerConfig(BaseModel):
    """One upstream MCP server that MiniGate fronts, over stdio or HTTP."""
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    command: list[str] = Field(
        default_factory=list, description="argv of the upstream stdio MCP server"
    )
    url: str | None = Field(default=None, description="Endpoint of a remote MCP server")
    auth_mode: str | None = Field(
        default=None,
        description="passthrough | bridge. Falls back to http.auth.mode when unset.",
    )
    """Per-server, because the right answer differs by upstream.

    Bridge mode requires MiniGate to register itself as an OAuth client with the
    upstream's authorization server. Linear supports dynamic registration; Google does
    not advertise a registration endpoint at all, so a gateway fronting both cannot use
    one mode for both. Setting this globally would mean breaking one upstream to fix the
    other.
    """
    authorization_servers: list[str] = Field(
        default_factory=list,
        description="Issuers advertised to clients for this server, normally the upstream's own",
    )
    scopes: list[str] = Field(default_factory=list, description="Scopes advertised to clients")
    resource_identifier: str | None = Field(
        default=None,
        description=(
            "Override the OAuth resource identifier advertised for this server. Unset, "
            "MiniGate advertises its own URL, which is correct under RFC 9728 — it is the "
            "resource server the client dialled. But the token comes from the UPSTREAM's "
            "authorization server, and one that honours RFC 8707 will not mint a token "
            "for a resource it does not own: the client binds to MiniGate's URI and the "
            "upstream rejects it. Observed with Linear, whose metadata declares "
            "'resource: https://mcp.linear.app/mcp'. Set this to the upstream's own "
            "identifier so the client requests an audience the upstream will honour. See "
            "docs/adr/002-oauth-passthrough.md."
        ),
    )
    policy: str | None = Field(default=None, description="Policy file override for this server")
    enabled: bool = Field(default=True)
    trust: str | int | None = Field(
        default=None,
        description="PUBLIC | INTERNAL | CONFIDENTIAL | RESTRICTED. Data may flow to equal "
        "or higher trust, never downward. Unset means INTERNAL.",
    )
    tool_trust: dict[str, str | int] = Field(
        default_factory=dict,
        description="Per-tool overrides, for servers that are both a source and a sink",
    )

    @model_validator(mode="after")
    def validate_upstream(self) -> ServerConfig:
        """Exactly one upstream: a stdio command or a remote URL."""
        if self.command and self.url:
            msg = "Server has both 'command' and 'url' — a server has one upstream, not two"
            raise ValueError(msg)
        if not self.command and not self.url:
            msg = "Server needs either 'command' (stdio) or 'url' (remote)"
            raise ValueError(msg)
        return self

    @property
    def is_remote(self) -> bool:
        return self.url is not None


class GatewayConfig(BaseModel):
    """Top-level MiniGate configuration."""
    # An unrecognised key is a configuration error, not something to ignore. A typo in
    # `policy` or `registry` would otherwise start a gateway that silently governs
    # nothing: the key is dropped, the field takes its default, and nothing in the logs
    # distinguishes that from a deliberate choice. Failing at startup is the cheapest
    # place to catch it.
    model_config = ConfigDict(extra="forbid")


    client_id: str = Field(default="unknown", description="Which MCP client this instance serves")
    policy: str | None = Field(default=None, description="Default policy file for all servers")
    database_url: str | None = Field(default=None, description="Audit store path or URL")
    fail_closed: bool = Field(
        default=False,
        description=(
            "On an internal gateway error, block the call instead of forwarding it. "
            "Default false: MiniGate's own faults must not break the agent. A rule "
            "that evaluates to BLOCK always blocks regardless of this setting."
        ),
    )
    dlp: DLPSettings = Field(default_factory=DLPSettings)
    injection: InjectionSettings = Field(default_factory=InjectionSettings)
    registry: RegistrySettings = Field(default_factory=RegistrySettings)
    lineage: LineageSettings = Field(default_factory=LineageSettings)
    http: HttpSettings = Field(default_factory=HttpSettings)
    sampling: SamplingSettings = Field(default_factory=SamplingSettings)
    elicitation: ElicitationSettings = Field(default_factory=ElicitationSettings)
    servers: dict[str, ServerConfig] = Field(default_factory=dict)

    def policy_for(self, server_name: str) -> str | None:
        """Resolve the policy file governing a given server."""
        server = self.servers.get(server_name)
        if server is not None and server.policy is not None:
            return server.policy
        return self.policy


class ConfigError(Exception):
    """Raised when a MiniGate configuration file is missing or invalid."""


def load_config(path: str) -> GatewayConfig:
    """Load and validate a MiniGate YAML configuration file.

    Args:
        path: Path to the YAML config.

    Returns:
        A validated GatewayConfig.

    Raises:
        ConfigError: If the file is missing, unparseable, or fails validation.
    """
    config_path = Path(path)
    if not config_path.exists():
        msg = f"MiniGate config not found: {path}"
        raise ConfigError(msg)

    try:
        raw = _expand_env(config_path.read_text(encoding="utf-8"), path)
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as e:
        msg = f"Invalid YAML in {path}: {e}"
        raise ConfigError(msg) from e

    try:
        config = GatewayConfig.model_validate(data)
    except Exception as e:
        msg = f"Invalid MiniGate config in {path}: {e}"
        raise ConfigError(msg) from e

    return _resolve_paths(config, config_path.resolve().parent)


_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand_env(text: str, path: str) -> str:
    """Substitute ${VAR} and ${VAR:-default} from the environment.

    A hosted deployment gets its public URL, database and per-tenant names from the
    platform, not from a file baked into the image — one image, many deployments.

    An unset variable with no default is an error rather than an empty string. A gateway
    that silently comes up advertising `public_url: ""` would answer OAuth discovery with
    a URL no client can reach, and the failure would surface as a client-side auth loop
    far from its cause.
    """
    missing: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        value = os.environ.get(name)
        if value is not None:
            return value
        if default is not None:
            return default
        missing.append(name)
        return ""

    expanded = _ENV_PATTERN.sub(replace, text)
    if missing:
        names = ", ".join(sorted(set(missing)))
        msg = f"{path} references unset environment variable(s): {names}"
        raise ConfigError(msg)
    return expanded


def _resolve_paths(config: GatewayConfig, base: Path) -> GatewayConfig:
    """Resolve relative file paths against the config file's own directory.

    MCP clients spawn servers with a working directory of their choosing — Claude Desktop
    uses "/" — so a relative path in the config cannot mean "relative to wherever this
    process happened to start". It has to mean "relative to the file it was written in",
    which is also what anyone editing that file expects.

    Absolute paths are left alone, as are values that are not file paths at all: a
    PostgreSQL URL, or SQLite's ":memory:".
    """

    def resolve(value: str | None) -> str | None:
        if not value or "://" in value or value.startswith(":"):
            return value
        candidate = Path(value)
        return value if candidate.is_absolute() else str(base / candidate)

    config.policy = resolve(config.policy)
    config.database_url = resolve(config.database_url)
    config.registry.path = resolve(config.registry.path) or config.registry.path
    config.lineage.store = resolve(config.lineage.store) or config.lineage.store
    for server in config.servers.values():
        server.policy = resolve(server.policy)
    return config
