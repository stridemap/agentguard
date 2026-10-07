"""Reading a remote server's tool manifest.

Without this path the registry — the control that defends against rug-pulls — could not
be populated for a hosted gateway, which fronts remote servers exclusively.
"""

from __future__ import annotations

import json

import httpx
import pytest

from minigate.discovery import DiscoveryError, fetch_tools_http

URL = "https://vendor.example/mcp"
AUTH = "Bearer upstream-token"


def _tools(n, prefix="tool"):
    return [{"name": f"{prefix}_{i}", "description": f"does {i}",
             "inputSchema": {"type": "object"}} for i in range(n)]


def test_a_manifest_is_read_over_http():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 100,
                                         "result": {"tools": _tools(3)}})

    tools = fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert [t["name"] for t in tools] == ["tool_0", "tool_1", "tool_2"]


def test_the_credential_is_sent():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(request.headers)
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 100, "result": {"tools": []}})

    fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert seen["authorization"] == AUTH
    assert "text/event-stream" in seen["accept"]


def test_a_manifest_delivered_as_sse_is_read():
    """Streamable HTTP servers may answer on an event stream rather than as JSON."""
    def handler(request: httpx.Request) -> httpx.Response:
        payload = {"jsonrpc": "2.0", "id": 100, "result": {"tools": _tools(2)}}
        return httpx.Response(200, content=f"data: {json.dumps(payload)}\n\n".encode(),
                              headers={"content-type": "text/event-stream"})

    tools = fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert len(tools) == 2


def test_pagination_is_followed():
    """A truncated manifest would silently approve a subset of the tool surface."""
    pages = [
        {"tools": _tools(2, "a"), "nextCursor": "c1"},
        {"tools": _tools(2, "b"), "nextCursor": "c2"},
        {"tools": _tools(1, "c")},
    ]
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        page = pages[calls["n"]]
        calls["n"] += 1
        if calls["n"] > 1:
            assert body["params"]["cursor"], "the cursor must be echoed back"
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": page})

    tools = fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert len(tools) == 5
    assert calls["n"] == 3


def test_an_unauthorized_read_names_the_challenge():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "invalid_token"},
                              headers={"www-authenticate": 'Bearer error="invalid_token"'})

    with pytest.raises(DiscoveryError, match="invalid_token"):
        fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_a_jsonrpc_error_is_surfaced():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 100,
                                         "error": {"code": -32601, "message": "no such method"}})

    with pytest.raises(DiscoveryError, match="no such method"):
        fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_an_unreachable_server_is_an_error_not_a_crash():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    with pytest.raises(DiscoveryError, match="Could not reach"):
        fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))


def test_no_tool_is_ever_called():
    """This is a manifest read. Calling a tool while approving it would be absurd."""
    methods = []

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(json.loads(request.content)["method"])
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 100, "result": {"tools": []}})

    fetch_tools_http(URL, AUTH, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert methods == ["tools/list"]
