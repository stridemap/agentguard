"""Stdio transport for MiniGate.

MCP over stdio is newline-delimited JSON. MiniGate splices itself into that pipe:

    client stdin  ──►  MiniGate  ──►  upstream stdin
    client stdout ◄──  MiniGate  ◄──  upstream stdout

Two pumps run concurrently, one per direction, because either side may speak first
and neither may block the other. Upstream stderr is inherited so the child's logs
reach the client's log file unchanged.

Anything MiniGate cannot parse is forwarded byte-for-byte. A shim that drops
messages it does not understand would break on the next protocol revision.

Correlation lives in `minigate.router`, shared with the HTTP gateway.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import sys
import threading
from typing import IO, Any

from minigate.core import GatewayCore
from minigate.logging import logger
from minigate.router import MessageRouter, PendingRequest, is_request, is_response

_DRAIN_TIMEOUT_SECONDS = 2.0

__all__ = ["PendingRequest", "StdioProxy", "run_stdio"]


class StdioProxy:
    """Pumps JSON-RPC between a client and an upstream MCP server, via GatewayCore.

    Streams are injected rather than opened here so the proxy can be driven from
    tests with ordinary pipes and no subprocess.
    """

    def __init__(
        self,
        core: GatewayCore,
        client_in: IO[str],
        client_out: IO[str],
        server_in: IO[str],
        server_out: IO[str],
    ) -> None:
        self.core = core
        self.client_in = client_in
        self.client_out = client_out
        self.server_in = server_in
        self.server_out = server_out
        self.router = MessageRouter()

    def run(self) -> None:
        """Pump both directions until either side closes."""
        upstream = threading.Thread(target=self._pump_to_server, name="minigate-c2s", daemon=True)
        downstream = threading.Thread(target=self._pump_to_client, name="minigate-s2c", daemon=True)
        upstream.start()
        downstream.start()

        # The downstream pump ends when the child's stdout closes, which is the
        # authoritative shutdown signal. Then give the upstream pump a moment to
        # finish any in-flight write — a block decision issued as the client
        # disconnects must still reach it — but never wait indefinitely, since that
        # pump is blocked reading a stdin that may never close.
        downstream.join()
        upstream.join(timeout=_DRAIN_TIMEOUT_SECONDS)

    # ── client → server ──────────────────────────────────────────────

    def _pump_to_server(self) -> None:
        try:
            for line in self.client_in:
                if not line.strip():
                    continue
                msg = _parse(line)
                if msg is None:
                    _write_raw(self.server_in, line)
                    continue

                # The client answering a request the server made. The payload is
                # travelling to the server, so it is governed on the way out.
                if is_response(msg):
                    answered = self.router.take_server_request(msg["id"])
                    if answered is not None:
                        _write_json(
                            self.server_in, self.core.on_client_response(msg, answered.method)
                        )
                        continue

                if is_request(msg):
                    self.router.note_client_request(msg)

                short_circuit = self.core.on_client_message(msg)
                if short_circuit is not None:
                    self.router.drop_client_request(msg.get("id"))
                    _write_json(self.client_out, short_circuit)
                    continue

                _write_json(self.server_in, msg)
        except Exception as e:
            logger.bind(module="minigate.proxy").warning("Client pump stopped: {error}", error=str(e))
        finally:
            _close(self.server_in)

    # ── server → client ──────────────────────────────────────────────

    def _pump_to_client(self) -> None:
        try:
            for line in self.server_out:
                if not line.strip():
                    continue
                msg = _parse(line)
                if msg is None:
                    _write_raw(self.client_out, line)
                    continue

                # A server-initiated request — sampling, elicitation. The reply goes back
                # upstream, not onward to the client.
                if is_request(msg):
                    rejection = self.core.on_server_request(msg)
                    if rejection is not None:
                        _write_json(self.server_in, rejection)
                        continue
                    self.router.note_server_request(msg)
                    _write_json(self.client_out, msg)
                    continue

                pending = (
                    self.router.take_client_request(msg["id"]) if is_response(msg) else None
                )
                _write_json(
                    self.client_out,
                    self.core.on_server_message(
                        msg,
                        pending.method if pending else None,
                        pending.tool if pending else None,
                        pending.uri if pending else None,
                        pending.prompt if pending else None,
                    ),
                )
        except Exception as e:
            logger.bind(module="minigate.proxy").warning("Server pump stopped: {error}", error=str(e))


def _parse(line: str) -> dict[str, Any] | None:
    """Parse a JSON-RPC line, or None if it is not a JSON object."""
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return None
    return msg if isinstance(msg, dict) else None


def _write_json(stream: IO[str], msg: dict[str, Any]) -> None:
    _write_raw(stream, json.dumps(msg, separators=(",", ":")) + "\n")


def _write_raw(stream: IO[str], text: str) -> None:
    try:
        stream.write(text if text.endswith("\n") else text + "\n")
        stream.flush()
    except (BrokenPipeError, ValueError):
        pass


def _close(stream: IO[str]) -> None:
    """Close upstream stdin — how a stdio MCP server is told to shut down."""
    with contextlib.suppress(Exception):
        stream.close()


def run_stdio(core: GatewayCore, command: list[str]) -> int:
    """Spawn an upstream MCP server and proxy this process's stdio to it.

    Args:
        core: The configured gateway decision layer.
        command: argv of the upstream stdio MCP server.

    Returns:
        The upstream process's exit code.
    """
    logger.bind(module="minigate.proxy").info(
        "Starting MiniGate for server '{server}' -> {command}",
        server=core.server,
        command=" ".join(command),
    )

    process = subprocess.Popen(  # noqa: S603 — argv comes from the operator's own config
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # inherit: upstream logs pass through to the client's log file
        text=True,
        bufsize=1,
    )

    if process.stdin is None or process.stdout is None:
        msg = "Failed to open pipes to the upstream MCP server"
        raise RuntimeError(msg)

    proxy = StdioProxy(
        core=core,
        client_in=sys.stdin,
        client_out=sys.stdout,
        server_in=process.stdin,
        server_out=process.stdout,
    )
    try:
        proxy.run()
    except KeyboardInterrupt:
        pass
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

    return process.returncode or 0
