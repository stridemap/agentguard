#!/usr/bin/env python3
"""Put MiniGate in or out of Claude Desktop's path, for with/without side-by-sides.

    python3 demo/minigate/gateway_toggle.py status
    python3 demo/minigate/gateway_toggle.py off     # direct to the vendor
    python3 demo/minigate/gateway_toggle.py on      # back through MiniGate

Then quit Claude Desktop with Cmd-Q and reopen. Closing the window is not enough — the
MCP servers are spawned by the app process, so they survive a window close and you will
be looking at the old path wondering why nothing changed.

This edits only mcpServers.<name> and leaves the rest of the file alone. Swapping whole
config copies is the obvious approach and the wrong one: that file also holds your
preferences, trusted folders and workspace state, so restoring yesterday's copy quietly
reverts today's settings.

Where the "off" command comes from: minigate.yaml already declares each server's upstream
under servers.<name>.command, because that is what the gateway spawns. Reading it back
means the two can never disagree about what the vendor endpoint is.

The first argument of that command is resolved to an absolute path. Claude Desktop is
launched from Finder with a minimal PATH, so a bare "npx" resolves interactively and then
fails silently under the app — the connector simply never appears.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
CONFIG = Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
MINIGATE = REPO / ".venv" / "bin" / "minigate"

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
)


def gateway_entry(server: str, config_path: Path) -> dict:
    return {
        "command": str(MINIGATE),
        "args": ["stdio", "--server-name", server, "--config", str(config_path)],
    }


def direct_entry(server: str, config_path: Path) -> dict:
    """The upstream command minigate.yaml says this server actually talks to."""
    declared = yaml.safe_load(config_path.read_text()).get("servers", {}).get(server)
    if not declared:
        raise SystemExit(f"{RED}no servers.{server} in {config_path}{RESET}")
    command = declared.get("command")
    if not command:
        raise SystemExit(
            f"{RED}servers.{server} has no command — it is a remote (url) server.{RESET}\n"
            f"{DIM}Point Claude Desktop at its url directly instead.{RESET}")
    resolved = shutil.which(command[0]) or command[0]
    entry = {"command": resolved, "args": list(command[1:])}

    # An absolute path is necessary but not sufficient. /usr/local/bin/npx is a script
    # whose shebang is "#!/usr/bin/env node", so it still needs node on PATH — and a
    # Finder-launched app gets /usr/bin:/bin:/usr/sbin:/sbin, where node is not. Verified:
    #   env -i PATH=/usr/bin:/bin /usr/local/bin/npx --version
    #   -> env: node: No such file or directory
    # So pin a PATH that contains the interpreter this command actually needs.
    interpreter = shutil.which("node")
    if interpreter:
        path = os.pathsep.join(dict.fromkeys([
            str(Path(interpreter).parent), str(Path(resolved).parent),
            "/usr/local/bin", "/opt/homebrew/bin", "/usr/bin", "/bin",
        ]))
        entry["env"] = {"PATH": path}
    return entry


def describe(entry: dict) -> str:
    if entry is None:
        return f"{DIM}not configured{RESET}"
    command = entry.get("command", "")
    if Path(command).name == "minigate":
        return f"{GREEN}through MiniGate{RESET}"
    return f"{YELLOW}direct to the vendor — no gateway{RESET}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Toggle MiniGate in Claude Desktop's path")
    parser.add_argument("mode", choices=["status", "on", "off"])
    parser.add_argument("--server-name", default="linear")
    parser.add_argument("--config", default=str(REPO / "minigate.yaml"),
                        help="minigate.yaml — read for the upstream command, and pointed "
                             "at by the 'on' entry")
    parser.add_argument("--desktop-config", default=str(CONFIG))
    args = parser.parse_args()

    desktop = Path(args.desktop_config)
    if not desktop.exists():
        print(f"{RED}no Claude Desktop config at {desktop}{RESET}")
        return 1

    data = json.loads(desktop.read_text())
    servers = data.setdefault("mcpServers", {})
    current = servers.get(args.server_name)

    print(f"\n{BOLD}{args.server_name}{RESET}  {describe(current)}")
    if current:
        rendered = " ".join([current.get("command", ""), *current.get("args", [])])
        print(f"  {DIM}{rendered}{RESET}")

    if args.mode == "status":
        others = [n for n in servers if n != args.server_name]
        if others:
            print(f"\n{DIM}  other servers, untouched: {', '.join(others)}{RESET}")
        print()
        return 0

    minigate_yaml = Path(args.config)
    wanted = (gateway_entry(args.server_name, minigate_yaml) if args.mode == "on"
              else direct_entry(args.server_name, minigate_yaml))

    if current == wanted:
        print(f"\n  {DIM}already {args.mode} — nothing to change{RESET}\n")
        return 0

    if args.mode == "on" and not MINIGATE.exists():
        print(f"\n  {RED}{MINIGATE} does not exist — refusing to point Claude Desktop{RESET}")
        print(f"  {RED}at a binary that is not there.{RESET}\n")
        return 1

    backup = desktop.with_suffix(".json.bak")
    backup.write_text(desktop.read_text())
    os.chmod(backup, 0o600)

    servers[args.server_name] = wanted
    # Write via a temp file in the same directory, then replace, so an interrupted write
    # cannot leave Claude Desktop with a truncated config it refuses to start from.
    temp = desktop.with_suffix(".json.tmp")
    temp.write_text(json.dumps(data, indent=4, ensure_ascii=False) + "\n")
    os.chmod(temp, 0o600)
    temp.replace(desktop)

    print(f"\n  now {describe(wanted)}")
    print(f"  {DIM}{' '.join([wanted['command'], *wanted['args']])}{RESET}")
    print(f"  {DIM}previous config saved to {backup.name}{RESET}")
    print(f"\n{BOLD}  Quit Claude Desktop with Cmd-Q and reopen.{RESET}")
    print(f"{DIM}  Closing the window does not restart the MCP servers.{RESET}")
    if args.mode == "off":
        print(f"\n{YELLOW}  With the gateway out of the path: nothing is written to the audit{RESET}")
        print(f"{YELLOW}  chain, and the S4 injection payloads reach the model intact.{RESET}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
