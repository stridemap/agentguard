#!/usr/bin/env python3
"""DEMO.md scenario 1, half two — the hidden tool, called anyway.

Filtering the tool list is not a security control on its own: nothing in the MCP
protocol stops a client calling a tool that was never listed. This script is that
client. It completes a normal handshake, notes which tools MiniGate delivered, then
deliberately calls one that was withheld.

Two things are proven:

  1. The call is refused by MiniGate, with the rule that refused it.
  2. The call never reaches the upstream vendor at all — established by counting the
     methods `mcp-remote` forwarded, not by taking MiniGate's word for it.

The sequencing matters. A real client waits for each response before sending the next
message, and MiniGate's registry can only verify a tool definition it has actually seen
advertised. Piping several JSON-RPC lines at once races that ordering and produces an
UNVERIFIED registry block instead of the policy block this scenario is about.

Safety: the call targets a non-existent id, so even if every control failed, the vendor
would answer "not found" rather than deleting anything real.

    python3 demo/minigate/scenario1_linear.py                    # defaults to Linear
    python3 demo/minigate/scenario1_linear.py --tool delete_attachment
"""

from __future__ import annotations

import argparse
import contextlib
import json
import re
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
# A non-existent id, so a failed block could still not delete anything real. Letters
# throughout on purpose: an all-digit id like 0000-0000-0000-0000 matches the policy
# engine's credit-card fallback regex, and the call is then refused by the wrong rule.
SAFE_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

BOLD, DIM, RED, GREEN, YELLOW, RESET = (
    "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[33m", "\033[0m"
)


def heading(step: str, text: str) -> None:
    print(f"\n{BOLD}{step}{RESET}  {text}")


def detail(text: str, colour: str = "") -> None:
    print(f"     {colour}{text}{RESET}")


class Gateway:
    """Drives MiniGate over stdio the way a real MCP client does."""

    def __init__(self, argv: list[str]) -> None:
        self.process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1, cwd=str(REPO),
        )
        self.upstream_methods: list[str] = []
        threading.Thread(target=self._drain_stderr, daemon=True).start()

    def _drain_stderr(self) -> None:
        """Collect what mcp-remote says it forwarded upstream."""
        for line in self.process.stderr:
            match = re.search(r"Local→Remote\]\s+([a-zA-Z/]+)", line)
            if match:
                self.upstream_methods.append(match.group(1))

    def send(self, message: dict) -> None:
        self.process.stdin.write(json.dumps(message) + "\n")
        self.process.stdin.flush()

    def request(self, rpc_id: int, method: str, params: dict | None = None) -> dict | None:
        """Send a request and wait for its answer, as a real client does."""
        self.send({"jsonrpc": "2.0", "id": rpc_id, "method": method, "params": params or {}})
        while True:
            line = self.process.stdout.readline()
            if not line:
                return None
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            if message.get("id") == rpc_id:
                return message

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.process.stdin.close()
            self.process.wait(timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser(description="MiniGate scenario 1, half two")
    parser.add_argument("--server-name", default="linear")
    parser.add_argument("--config", default=str(REPO / "minigate.yaml"))
    parser.add_argument("--tool", default="delete_comment", help="a tool the policy withholds")
    args = parser.parse_args()

    gateway = Gateway([
        str(REPO / ".venv" / "bin" / "minigate"), "stdio",
        "--server-name", args.server_name, "--config", args.config,
    ])

    print(f"\n{BOLD}Scenario 1, half two — calling a tool that was never offered{RESET}")
    print(f"{DIM}server: {args.server_name}   target: {args.tool}{RESET}")

    heading("1.", "Handshake, exactly as any MCP client does")
    initialized = gateway.request(1, "initialize", {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "scenario1-demo", "version": "1.0"},
    })
    if initialized is None:
        detail("gateway did not respond — is the config path right?", RED)
        return 1
    server = initialized.get("result", {}).get("serverInfo", {}).get("name", "unknown")
    detail(f"connected to {server} through MiniGate", GREEN)

    gateway.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    heading("2.", "Ask for the tool list — and wait for it, as a real client would")
    listed = gateway.request(2, "tools/list")
    tools = listed.get("result", {}).get("tools", []) if listed else []
    names = [t.get("name", "") for t in tools]
    withheld_shape = [n for n in names if n.startswith("delete")]
    detail(f"MiniGate delivered {len(names)} tools")
    detail(f"any delete_* among them? {withheld_shape or 'none — all withheld'}",
           GREEN if not withheld_shape else RED)
    detail(f"is '{args.tool}' in the list? {'yes' if args.tool in names else 'NO'}",
           RED if args.tool in names else GREEN)

    heading("3.", f"Call '{args.tool}' anyway — the model was never shown it, but nothing stops us")
    detail(f"using id={SAFE_ID} so a failed block could still not delete anything real", DIM)
    called = gateway.request(3, "tools/call", {"name": args.tool, "arguments": {"id": SAFE_ID}})
    result = (called or {}).get("result", {})
    is_error = result.get("isError")
    text = (result.get("content") or [{}])[0].get("text", "")

    if is_error:
        detail("REFUSED", GREEN)
        for chunk in [text[i:i + 92] for i in range(0, min(len(text), 276), 92)]:
            detail(chunk, DIM)
    else:
        detail("NOT REFUSED — the call went through. Investigate before demoing this.", RED)

    heading("4.", "Did it reach the vendor? Count what was forwarded upstream")
    gateway.close()
    forwarded = gateway.upstream_methods
    for method in sorted(set(forwarded)):
        detail(f"{forwarded.count(method)}x  {method}")
    if "tools/call" in forwarded:
        detail("tools/call WAS forwarded — the block did not hold", RED)
        return 1
    detail("tools/call was never forwarded — the call died at the gateway", GREEN)

    print(f"\n{BOLD}The point{RESET}")
    print("     Filtering the list is not enough on its own — nothing in the protocol")
    print("     stops a client calling a tool it never listed, and we just tried.")
    print("     Gating alone is not enough either: the model would keep planning around")
    print("     a tool it can never use. Both halves, or neither works.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
