"""Minimal MCP client used to read a server's tool manifest.

Only what `minigate registry sync` needs: complete the handshake, page through
`tools/list`, and exit. This is a read of the manifest, not a session — no tool is
ever called, so pointing it at an unfamiliar server is safe.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

from minigate import __version__
from minigate.logging import logger

_PROTOCOL_VERSION = "2025-06-18"
_READ_TIMEOUT_SECONDS = 30.0
_MAX_PAGES = 50


class DiscoveryError(Exception):
    """Raised when a server's tool manifest could not be read."""


def fetch_tools(command: list[str], timeout: float = _READ_TIMEOUT_SECONDS) -> list[dict[str, Any]]:
    """Start an upstream stdio MCP server and return everything it advertises.

    Args:
        command: argv of the upstream MCP server.
        timeout: Seconds to wait for the whole exchange.

    Returns:
        The tool definitions, in the order the server listed them.

    Raises:
        DiscoveryError: If the server could not be started or did not respond.
    """
    logger.bind(module="minigate.discovery").info(
        "Reading tool manifest from: {command}", command=" ".join(command)
    )
    try:
        process = subprocess.Popen(  # noqa: S603 — argv comes from the operator's own config
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
    except (OSError, ValueError) as e:
        msg = f"Could not start upstream server {command!r}: {e}"
        raise DiscoveryError(msg) from e

    try:
        return _handshake_and_list(process, timeout)
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def _handshake_and_list(process: subprocess.Popen, timeout: float) -> list[dict[str, Any]]:
    stdin, stdout = process.stdin, process.stdout
    if stdin is None or stdout is None:
        msg = "Failed to open pipes to the upstream MCP server"
        raise DiscoveryError(msg)

    _send(
        stdin,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "minigate", "version": __version__},
            },
        },
    )
    if _read_response(stdout, 1, timeout) is None:
        msg = "Upstream server did not respond to initialize"
        raise DiscoveryError(msg)

    _send(stdin, {"jsonrpc": "2.0", "method": "notifications/initialized"})

    tools: list[dict[str, Any]] = []
    cursor: str | None = None
    for page in range(_MAX_PAGES):
        rpc_id = 100 + page
        params = {"cursor": cursor} if cursor else {}
        _send(stdin, {"jsonrpc": "2.0", "id": rpc_id, "method": "tools/list", "params": params})

        response = _read_response(stdout, rpc_id, timeout)
        if response is None:
            msg = "Upstream server did not respond to tools/list"
            raise DiscoveryError(msg)
        if "error" in response:
            msg = f"Upstream server returned an error for tools/list: {response['error']}"
            raise DiscoveryError(msg)

        result = response.get("result", {})
        tools.extend(t for t in result.get("tools", []) if isinstance(t, dict))

        cursor = result.get("nextCursor")
        if not cursor:
            return tools

    logger.bind(module="minigate.discovery").warning(
        "Stopped paging tools/list after {pages} pages — manifest may be incomplete", pages=_MAX_PAGES
    )
    return tools


def _send(stream: Any, msg: dict[str, Any]) -> None:
    stream.write(json.dumps(msg, separators=(",", ":")) + "\n")
    stream.flush()


def _read_response(stream: Any, rpc_id: int, timeout: float) -> dict[str, Any] | None:
    """Read lines until the response with the given id arrives.

    Notifications and log lines interleave freely on this stream, so anything that
    is not the awaited response is skipped rather than treated as an error.
    """
    import select

    deadline = _now() + timeout
    while _now() < deadline:
        remaining = max(0.0, deadline - _now())
        ready, _, _ = select.select([stream], [], [], remaining)
        if not ready:
            continue
        line = stream.readline()
        if not line:
            return None
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(msg, dict) and msg.get("id") == rpc_id:
            return msg
    return None


def _now() -> float:
    import time

    return time.monotonic()
