"""MiniGate command-line interface.

    # Run as a stdio shim in front of an MCP server
    minigate stdio --server-name notion -- npx -y mcp-remote https://mcp.notion.com/mcp

    # Same, with the upstream command taken from a config file
    minigate stdio --server-name notion --config minigate.yaml

    # Print the claude_desktop_config.json fragment for a configured server
    minigate snippet --server-name notion --config minigate.yaml

    # Verify the audit chain has not been tampered with
    minigate verify --database minigate.db
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from agentguard.policy_engine import PolicyEngine
from minigate import __version__
from minigate.config import ConfigError, GatewayConfig, load_config
from minigate.core import GatewayCore
from minigate.discovery import DiscoveryError, fetch_tools
from minigate.guardrails import Guardrails
from minigate.lineage import LineageTracker, TaintStore, TrustLevel
from minigate.logging import logger
from minigate.oauth_client import OAuthError
from minigate.proxy import run_stdio
from minigate.registry import RegistryMode, ToolRegistry
from minigate.store import create_sink


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="minigate", description="MCP protocol gateway for AI agents")
    parser.add_argument("--version", action="version", version=f"minigate {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("stdio", help="Front an upstream stdio MCP server")
    run.add_argument("--server-name", required=True, help="Name for this server, used in policy rules")
    run.add_argument("--config", help="Path to minigate.yaml")
    run.add_argument("--policy", help="Policy file (overrides the config's)")
    run.add_argument("--client-id", help="Which MCP client this serves (overrides the config's)")
    run.add_argument("--database", help="Audit store path or URL (overrides the config's)")
    run.add_argument(
        "--fail-closed",
        action="store_true",
        help="Block calls MiniGate cannot evaluate. Default is fail-open.",
    )
    run.add_argument(
        "upstream",
        nargs=argparse.REMAINDER,
        help="-- followed by the upstream server argv (omit if given in --config)",
    )

    tools = sub.add_parser("tools", help="List what a server advertises, with policy verdicts")
    tools.add_argument("--server-name", required=True)
    tools.add_argument("--config", help="Path to minigate.yaml")
    tools.add_argument("--policy", help="Policy file (overrides the config's)")
    tools.add_argument("--json", action="store_true", help="Machine-readable output")
    tools.add_argument("upstream", nargs=argparse.REMAINDER)

    serve = sub.add_parser("serve", help="Run the remote HTTP gateway")
    serve.add_argument("--config", required=True, help="Path to minigate.yaml")
    serve.add_argument("--host", help="Bind address (overrides the config's)")
    serve.add_argument("--port", type=int, help="Bind port (overrides the config's)")

    snippet = sub.add_parser("snippet", help="Print a claude_desktop_config.json fragment")
    snippet.add_argument("--server-name", required=True)
    snippet.add_argument("--config", required=True)

    probe = sub.add_parser(
        "oauth-probe",
        help="Prove MiniGate can obtain a usable token from an upstream on its own behalf",
    )
    probe.add_argument("--resource-url", help="Upstream MCP endpoint, e.g. https://mcp.linear.app/mcp")
    probe.add_argument("--server-name", help="Take the URL from this configured server instead")
    probe.add_argument("--config", help="Path to minigate.yaml")
    probe.add_argument("--no-browser", action="store_true", help="Print the URL, do not open it")

    verify = sub.add_parser("verify", help="Verify the audit chain")
    verify.add_argument("--database", help="Audit store path or URL")

    registry = sub.add_parser("registry", help="Manage the approved-tool registry")
    registry_sub = registry.add_subparsers(dest="registry_command", required=True)

    reg_sync = registry_sub.add_parser("sync", help="Read a server's tools and approve them")
    reg_sync.add_argument("--server-name", required=True)
    reg_sync.add_argument("--config", help="Path to minigate.yaml")
    reg_sync.add_argument("--registry", help="Registry file (overrides the config's)")
    reg_sync.add_argument("--approved-by", default="unknown", help="Who reviewed these tools")
    reg_sync.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing"
    )
    reg_sync.add_argument("upstream", nargs=argparse.REMAINDER)

    reg_diff = registry_sub.add_parser("diff", help="Compare a server's tools against the registry")
    reg_diff.add_argument("--server-name", required=True)
    reg_diff.add_argument("--config", help="Path to minigate.yaml")
    reg_diff.add_argument("--registry", help="Registry file (overrides the config's)")
    reg_diff.add_argument("upstream", nargs=argparse.REMAINDER)

    reg_list = registry_sub.add_parser("list", help="List approved tools")
    reg_list.add_argument("--config", help="Path to minigate.yaml")
    reg_list.add_argument("--registry", help="Registry file (overrides the config's)")
    reg_list.add_argument("--server-name", help="Only show tools for this server")

    return parser


def _resolve_upstream(args: argparse.Namespace, config: GatewayConfig) -> list[str]:
    """Take the upstream argv from the command line, else from the config file."""
    upstream = [a for a in (args.upstream or []) if a != "--"]
    if upstream:
        return upstream
    server = config.servers.get(args.server_name)
    if server is None or not server.command:
        msg = (
            f"No upstream command for server '{args.server_name}'. Pass it after '--' "
            f"or define servers.{args.server_name}.command in the config."
        )
        raise ConfigError(msg)
    return server.command


def build_core(
    config: GatewayConfig,
    server_name: str,
    *,
    sink=None,
    policy_path: str | None = None,
    client_id: str | None = None,
    fail_closed: bool = False,
) -> GatewayCore:
    """Assemble a GatewayCore from configuration.

    Shared by both transports: stdio builds one, the HTTP gateway builds one per
    configured server. Keeping this in one place is what makes the two transports
    provably equivalent in what they enforce.
    """
    resolved_policy = policy_path or config.policy_for(server_name)
    if resolved_policy is None:
        logger.bind(module="minigate").warning(
            "No policy file configured for {server} — calls will be allowed and audited only",
            server=server_name,
        )

    registry = None
    if config.registry.enabled:
        registry = ToolRegistry(path=config.registry.path, mode=config.registry.mode)
        if registry.mode == RegistryMode.ENFORCE and not registry.entries:
            logger.bind(module="minigate").warning(
                "Registry is in enforce mode but empty — every tool will be withheld. "
                "Run 'minigate registry sync --server-name {server}' first.",
                server=server_name,
            )

    lineage = None
    if config.lineage.enabled and config.lineage.mode != "off":
        lineage = LineageTracker(
            store=TaintStore(config.lineage.store, config.lineage.ttl_seconds),
            min_value_length=config.lineage.min_value_length,
            max_values_per_result=config.lineage.max_values_per_result,
        )

    server_config = config.servers.get(server_name)
    return GatewayCore(
        server=server_name,
        policy=PolicyEngine(resolved_policy),
        guardrails=Guardrails(config.dlp, config.injection),
        sink=sink if sink is not None else create_sink(config.database_url),
        client_id=client_id or config.client_id,
        fail_closed=fail_closed or config.fail_closed,
        registry=registry,
        lineage=lineage,
        lineage_mode=config.lineage.mode,
        server_trust=TrustLevel.parse(server_config.trust if server_config else None),
        tool_trust={
            tool: TrustLevel.parse(level)
            for tool, level in (server_config.tool_trust if server_config else {}).items()
        },
        sampling_settings=config.sampling,
        elicitation_settings=config.elicitation,
    )


def _cmd_stdio(args: argparse.Namespace) -> int:
    config = load_config(args.config) if args.config else GatewayConfig()
    upstream = _resolve_upstream(args, config)
    core = build_core(
        config,
        args.server_name,
        sink=create_sink(args.database or config.database_url),
        policy_path=args.policy,
        client_id=args.client_id,
        fail_closed=args.fail_closed,
    )
    return run_stdio(core, upstream)


def _cmd_tools(args: argparse.Namespace) -> int:
    """Inventory a server: every tool it advertises, and what policy would do about it.

    The first thing anyone should run against an unfamiliar MCP server. It reads the
    manifest and never calls a tool, so pointing it at something you have not reviewed
    is safe.
    """
    from minigate.guardrails import Guardrails
    from minigate.models import Direction, McpEvent

    config = load_config(args.config) if args.config else GatewayConfig()
    policy_path = args.policy or config.policy_for(args.server_name)
    policy = PolicyEngine(policy_path)
    guardrails = Guardrails(config.dlp, config.injection)

    advertised = fetch_tools(_resolve_upstream(args, config))

    rows = []
    for tool in advertised:
        name = tool.get("name", "")
        probe = McpEvent(
            server=args.server_name,
            method="tools/list",
            tool=name,
            direction=Direction.RESPONSE,
        )
        decision = policy.evaluate(probe.to_agent_event())
        poisoned = guardrails.scan_tool_description(tool.get("description") or "") == "INJECTED"
        rows.append(
            {
                "tool": name,
                "qualified": probe.qualified_tool,
                "verdict": "FLAGGED" if poisoned else decision.result,
                "rule": decision.matched_rule,
                "reason": "description scored INJECTED" if poisoned else decision.reason,
                "exposed": not poisoned and decision.result != "BLOCK",
                "description": (tool.get("description") or "")[:90],
            }
        )
    rows.sort(key=lambda r: (r["exposed"], r["tool"]))

    if args.json:
        print(json.dumps({"server": args.server_name, "tools": rows}, indent=2))  # noqa: T201
        return 0

    if policy_path is None:
        print("No policy configured — every tool would be exposed.\n")  # noqa: T201

    width = max((len(r["tool"]) for r in rows), default=4) + 2
    print(f"{args.server_name} — {len(rows)} tools advertised\n")  # noqa: T201
    print(f"  {'VERDICT':<9} {'TOOL':<{width}} WHY")  # noqa: T201
    print(f"  {'-' * 9} {'-' * width} {'-' * 40}")  # noqa: T201
    for r in rows:
        why = r["rule"] or ("" if r["exposed"] else r["reason"][:40])
        if r["verdict"] == "FLAGGED":
            why = r["reason"]
        print(f"  {r['verdict']:<9} {r['tool']:<{width}} {why}")  # noqa: T201

    exposed = sum(1 for r in rows if r["exposed"])
    flagged = sum(1 for r in rows if r["verdict"] == "FLAGGED")
    print(  # noqa: T201
        f"\n  {exposed} exposed to the model · {len(rows) - exposed} withheld"
        + (f" · {flagged} flagged as poisoned" if flagged else "")
    )
    return 0


def _cmd_serve(args: argparse.Namespace) -> int:
    """Run the remote gateway over HTTP."""
    import uvicorn

    from minigate.http_gateway import GatewayApp, create_app

    config = load_config(args.config)
    remote = {name: s for name, s in config.servers.items() if s.is_remote and s.enabled}
    if not remote:
        msg = (
            "No remote servers configured. A server needs a 'url:' to be served over HTTP; "
            "servers with a 'command:' are stdio-only."
        )
        raise ConfigError(msg)

    host = args.host or config.http.host
    port = args.port or config.http.port
    if config.http.auth.require and config.http.auth.mode == "none":
        logger.bind(module="minigate").warning(
            "auth.mode is 'none' — every request is accepted. Bind to localhost only."
        )

    bridge = None
    if config.http.auth.mode == "bridge":
        from minigate.bridge import OAuthBridge
        from minigate.bridge_sql_store import SqlGrantStore

        if not config.http.public_url:
            msg = (
                "Bridge mode needs http.public_url: it is the issuer the gateway "
                "advertises and the address an upstream redirects back to."
            )
            raise ConfigError(msg)

        # Grants live beside the audit chain but in their own store — one is a record of
        # what happened, the other holds live third-party credentials.
        # MINIGATE_GRANT_URL first, then the config, then whatever the audit chain uses.
        # The hosted config deliberately leaves database_url unset so the audit store
        # reads DATABASE_URL itself — without this, grants would silently land in a
        # SQLite file on an ephemeral disk and every redeploy would lose them.
        grants_url = (
            os.environ.get("MINIGATE_GRANT_URL")
            or config.database_url
            or os.environ.get("DATABASE_URL")
        )
        if not grants_url:
            grants_url = "minigate-grants.db"
            logger.bind(module="minigate").warning(
                "No grant store URL; falling back to {path}. On a platform with "
                "ephemeral disk this loses every grant on redeploy.",
                path=grants_url,
            )
        bridge = OAuthBridge(
            config,
            SqlGrantStore(grants_url),
            sink=create_sink(config.database_url),
        )
        logger.bind(module="minigate").info(
            "Bridge mode: MiniGate is the authorization server at {issuer}",
            issuer=config.http.public_url.rstrip("/"),
        )

    app_state = GatewayApp(
        config=config,
        cores={name: build_core(config, name) for name in remote},
        bridge=bridge,
    )
    logger.bind(module="minigate").info(
        "MiniGate serving {count} server(s) on http://{host}:{port}/mcp/<server>",
        count=len(remote),
        host=host,
        port=port,
    )
    uvicorn.run(create_app(app_state), host=host, port=port, log_config=None)
    return 0


def _cmd_snippet(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    server = config.servers.get(args.server_name)
    if server is None:
        msg = f"Server '{args.server_name}' is not defined in {args.config}"
        raise ConfigError(msg)

    # Absolute paths, both of them. Claude Desktop spawns MCP servers with a minimal
    # PATH and a working directory of "/", so a bare "minigate" is not found and a
    # relative config path resolves against the wrong directory. This is the single
    # most common reason a correctly-written config silently fails to start.
    # Prefer the console script beside the running interpreter over a PATH lookup:
    # PATH may point at a different (stale) virtualenv, and the process you invoked is
    # the one you meant.
    sibling = Path(sys.executable).with_name("minigate")
    executable = str(sibling) if sibling.exists() else (shutil.which("minigate") or "minigate")
    fragment = {
        "mcpServers": {
            args.server_name: {
                "command": executable,
                "args": [
                    "stdio",
                    "--server-name",
                    args.server_name,
                    "--config",
                    str(Path(args.config).resolve()),
                ],
            }
        }
    }
    # stdout is the protocol channel only while proxying; here it is the CLI's output.
    print(json.dumps(fragment, indent=2))  # noqa: T201
    return 0


def _load_registry(args: argparse.Namespace, config: GatewayConfig) -> ToolRegistry:
    """Open the registry named on the command line, else the one in the config."""
    return ToolRegistry(path=args.registry or config.registry.path, mode=RegistryMode.OBSERVE)


def _cmd_registry_sync(args: argparse.Namespace) -> int:
    config = load_config(args.config) if args.config else GatewayConfig()
    registry = _load_registry(args, config)
    tools = fetch_tools(_resolve_upstream(args, config))

    changes = registry.diff(args.server_name, tools)
    for label in ("new", "changed", "unchanged", "missing"):
        for name in changes[label]:
            print(f"  {label:<10} {args.server_name}.{name}")  # noqa: T201

    if args.dry_run:
        print(f"\nDry run — {args.registry or config.registry.path} not written.")  # noqa: T201
        return 0

    for tool in tools:
        registry.approve(args.server_name, tool, approved_by=args.approved_by)
    # Tools the server no longer advertises stay approved: revoking automatically
    # would let a server launder a definition change through a disappear/reappear.
    registry.save()

    approved = len(changes["new"]) + len(changes["changed"])
    print(  # noqa: T201
        f"\nApproved {len(tools)} tools for '{args.server_name}' "
        f"({approved} new or changed) -> {registry.path}"
    )
    if changes["missing"]:
        print(  # noqa: T201
            f"Note: {len(changes['missing'])} approved tools are no longer advertised. "
            "Remove them with 'registry revoke' if that is expected."
        )
    return 0


def _cmd_registry_diff(args: argparse.Namespace) -> int:
    config = load_config(args.config) if args.config else GatewayConfig()
    registry = _load_registry(args, config)
    changes = registry.diff(args.server_name, fetch_tools(_resolve_upstream(args, config)))

    print(json.dumps(changes, indent=2))  # noqa: T201
    # Non-zero when review is needed, so this can gate a CI check.
    return 1 if changes["new"] or changes["changed"] else 0


def _cmd_registry_list(args: argparse.Namespace) -> int:
    config = load_config(args.config) if args.config else GatewayConfig()
    registry = _load_registry(args, config)

    entries = [e for e in registry.entries if not args.server_name or e.server == args.server_name]
    if not entries:
        print("No approved tools.")  # noqa: T201
        return 0
    for entry in entries:
        print(f"  {entry.server}.{entry.name:<30} {entry.hash[:12]}  {entry.approved_at}")  # noqa: T201
    print(f"\n{len(entries)} approved tools in {registry.path}")  # noqa: T201
    return 0


def _cmd_registry(args: argparse.Namespace) -> int:
    handlers = {"sync": _cmd_registry_sync, "diff": _cmd_registry_diff, "list": _cmd_registry_list}
    return handlers[args.registry_command](args)


def _cmd_verify(args: argparse.Namespace) -> int:
    from agentguard.store_factory import create_store

    store = create_store(args.database)
    try:
        result = store.verify_chain()
        print(json.dumps(result, indent=2, default=str))  # noqa: T201
        return 0 if result.get("is_valid", False) else 1
    finally:
        store.close()


def _cmd_oauth_probe(args: argparse.Namespace) -> int:
    """Run the upstream OAuth proving step.

    Step 1 of the bridge: with MiniGate as the OAuth client asking for the resource the
    upstream owns, does the resulting token work? Nothing is persisted and nothing is
    wired into the proxy — this only answers that question.
    """
    url = args.resource_url
    if not url:
        if not args.server_name:
            logger.bind(module="minigate").error(
                "Give either --resource-url or --server-name with --config"
            )
            return 2
        config = load_config(args.config)
        server = config.servers.get(args.server_name)
        if server is None:
            logger.bind(module="minigate").error(
                "No server named {name} in the config", name=args.server_name
            )
            return 2
        if not server.url:
            logger.bind(module="minigate").error(
                "Server {name} is a stdio upstream; this probe needs a remote URL",
                name=args.server_name,
            )
            return 2
        url = server.url

    from minigate.oauth_probe import run_probe

    return run_probe(url, open_browser=not args.no_browser)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = _build_parser().parse_args(argv)
    handlers = {
        "stdio": _cmd_stdio,
        "serve": _cmd_serve,
        "tools": _cmd_tools,
        "snippet": _cmd_snippet,
        "verify": _cmd_verify,
        "registry": _cmd_registry,
        "oauth-probe": _cmd_oauth_probe,
    }
    try:
        return handlers[args.command](args)
    except (ConfigError, DiscoveryError, OAuthError) as e:
        logger.bind(module="minigate").error("{error}", error=str(e))
        return 2


if __name__ == "__main__":
    sys.exit(main())
