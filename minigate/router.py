"""Request/response correlation, shared by every transport.

Governing a response needs to know what it answers: a `tools/call` result must be
evaluated under the same qualified name as the call, and a `resources/read` result under
the URI that was asked for. JSON-RPC ids alone do not carry that, so each in-flight
request is remembered until its answer arrives.

The two directions are tracked separately on purpose. Each side mints its own ids, so a
server's id 1 and a client's id 1 are unrelated — one map would mistake a client request
for the answer to a server request.

Transport-agnostic and I/O-free: `StdioProxy` holds one of these per process, the HTTP
gateway holds one per MCP session.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PendingRequest:
    """An in-flight request, remembered so its response can be governed in context."""

    method: str
    tool: str | None = None
    uri: str | None = None
    prompt: str | None = None

    @classmethod
    def from_message(cls, msg: dict[str, Any]) -> PendingRequest:
        """Extract the governing context from a JSON-RPC request.

        `tools/call` and `prompts/get` both carry their target in `params.name`, so the
        method decides which field it lands in — conflating them would let a rule written
        for a tool silently govern a prompt of the same name.
        """
        method = str(msg.get("method", ""))
        params = msg.get("params") or {}
        return cls(
            method=method,
            tool=params.get("name") if method == "tools/call" else None,
            uri=params.get("uri") if method.startswith("resources/") else None,
            prompt=params.get("name") if method == "prompts/get" else None,
        )


def is_request(msg: dict[str, Any]) -> bool:
    """A JSON-RPC request: has a method and expects an answer."""
    return msg.get("method") is not None and msg.get("id") is not None


def is_notification(msg: dict[str, Any]) -> bool:
    """A JSON-RPC notification: has a method, expects no answer."""
    return msg.get("method") is not None and msg.get("id") is None


def is_response(msg: dict[str, Any]) -> bool:
    """A JSON-RPC response: answers an id, carries no method."""
    return msg.get("method") is None and msg.get("id") is not None


class MessageRouter:
    """Tracks in-flight requests in both directions. Thread-safe."""

    def __init__(self) -> None:
        self._client_requests: dict[str, PendingRequest] = {}
        self._server_requests: dict[str, PendingRequest] = {}
        self._lock = threading.Lock()

    # ── client → server ──────────────────────────────────────────────

    def note_client_request(self, msg: dict[str, Any]) -> None:
        with self._lock:
            self._client_requests[str(msg["id"])] = PendingRequest.from_message(msg)

    def take_client_request(self, rpc_id: Any) -> PendingRequest | None:
        """Claim the client request an incoming response answers, if it is known."""
        with self._lock:
            return self._client_requests.pop(str(rpc_id), None)

    def drop_client_request(self, rpc_id: Any) -> None:
        """Forget a client request that was answered locally and never forwarded."""
        with self._lock:
            self._client_requests.pop(str(rpc_id), None)

    # ── server → client ──────────────────────────────────────────────

    def note_server_request(self, msg: dict[str, Any]) -> None:
        with self._lock:
            self._server_requests[str(msg["id"])] = PendingRequest.from_message(msg)

    def take_server_request(self, rpc_id: Any) -> PendingRequest | None:
        with self._lock:
            return self._server_requests.pop(str(rpc_id), None)

    @property
    def in_flight(self) -> int:
        with self._lock:
            return len(self._client_requests) + len(self._server_requests)
