"""Tests for MiniGate's stdio transport and config loading."""

from __future__ import annotations

import io
import json

import pytest

from agentguard.policy_engine import PolicyEngine
from minigate.config import (
    ConfigError,
    DLPSettings,
    GatewayConfig,
    InjectionSettings,
    load_config,
)
from minigate.core import GatewayCore
from minigate.guardrails import Guardrails
from minigate.proxy import StdioProxy

POLICY_YAML = """
rules:
  - id: P-BLOCK
    name: Block deletes
    priority: 10
    conditions:
      tool_name: "fs\\\\.delete_file"
    action: BLOCK
"""


@pytest.fixture
def core(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(POLICY_YAML, encoding="utf-8")
    return GatewayCore(
        server="fs",
        policy=PolicyEngine(str(path)),
        guardrails=Guardrails(
            DLPSettings(enabled=False), InjectionSettings(enabled=False)
        ),
    )


class _Stream(io.StringIO):
    """A StringIO that survives close().

    The proxy closes upstream stdin when the client disconnects — that is how a real
    MCP server is told to shut down — but the test still needs to read what was written.
    """

    def close(self) -> None:
        pass


def _proxy(core, client_lines: str = "", server_lines: str = ""):
    return StdioProxy(
        core=core,
        client_in=_Stream(client_lines),
        client_out=_Stream(),
        server_in=_Stream(),
        server_out=_Stream(server_lines),
    )


def _messages(stream: io.StringIO) -> list[dict]:
    return [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]


# ── client → server ──────────────────────────────────────────────────


def test_allowed_call_reaches_upstream(core):
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "read_file"},
        }
    )
    proxy = _proxy(core, client_lines=request + "\n")

    proxy.run()

    assert [m["params"]["name"] for m in _messages(proxy.server_in)] == ["read_file"]
    assert _messages(proxy.client_out) == []


def test_blocked_call_never_reaches_upstream(core):
    request = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "delete_file"},
        }
    )
    proxy = _proxy(core, client_lines=request + "\n")

    proxy.run()

    assert _messages(proxy.server_in) == []
    replies = _messages(proxy.client_out)
    assert len(replies) == 1
    assert replies[0]["result"]["isError"] is True


def test_unparseable_lines_are_forwarded_rather_than_dropped(core):
    """A shim that drops what it cannot parse breaks on the next protocol revision."""
    proxy = _proxy(core, client_lines="not json at all\n")

    proxy.run()

    assert proxy.server_in.getvalue().strip() == "not json at all"


def test_blank_lines_are_ignored(core):
    proxy = _proxy(core, client_lines="\n\n")

    proxy.run()

    assert proxy.server_in.getvalue() == ""


# ── request/response correlation ─────────────────────────────────────


def test_responses_are_correlated_to_their_request_method(core):
    """tools/list filtering depends on knowing which request a response answers."""
    request = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/list"})
    proxy = _proxy(core, client_lines=request + "\n")
    proxy.run()

    response = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 7,
            "result": {
                "tools": [
                    {"name": "read_file", "description": "Read"},
                    {"name": "delete_file", "description": "Delete"},
                ]
            },
        }
    )
    proxy.client_in = _Stream("")
    proxy.server_out = _Stream(response + "\n")
    proxy.client_out = _Stream()
    proxy.run()

    delivered = _messages(proxy.client_out)
    assert [t["name"] for t in delivered[0]["result"]["tools"]] == ["read_file"]


def _capture_correlation(proxy, request: dict, response: dict) -> dict:
    """Drive one request/response pair and capture what the core was told about it."""
    proxy.client_in = _Stream(json.dumps(request) + "\n")
    proxy.run()

    seen: dict = {}
    proxy.core.on_server_message = (  # type: ignore[method-assign]
        lambda msg, method, tool=None, uri=None, prompt=None: seen.update(
            method=method, tool=tool, uri=uri, prompt=prompt
        )
        or msg
    )

    proxy.client_in = _Stream("")
    proxy.server_out = _Stream(json.dumps(response) + "\n")
    proxy.run()
    return seen


def test_tool_call_responses_carry_the_tool_name_forward(core):
    """The response handler needs the tool, not just the method, to evaluate policy."""
    seen = _capture_correlation(
        _proxy(core),
        {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "read_file"},
        },
        {"jsonrpc": "2.0", "id": 8, "result": {}},
    )

    assert seen == {
        "method": "tools/call",
        "tool": "read_file",
        "uri": None,
        "prompt": None,
    }


def test_prompt_get_responses_carry_the_prompt_name_forward(core):
    """prompts/get uses params.name like tools/call — the two must not be conflated."""
    seen = _capture_correlation(
        _proxy(core),
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "prompts/get",
            "params": {"name": "summarize"},
        },
        {"jsonrpc": "2.0", "id": 11, "result": {}},
    )

    assert seen == {
        "method": "prompts/get",
        "tool": None,
        "uri": None,
        "prompt": "summarize",
    }


def test_resource_read_responses_carry_the_uri_forward(core):
    """Same reasoning as the tool name: policy addresses resources by URI."""
    seen = _capture_correlation(
        _proxy(core),
        {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "resources/read",
            "params": {"uri": "file:///tmp/notes.md"},
        },
        {"jsonrpc": "2.0", "id": 9, "result": {}},
    )

    assert seen == {
        "method": "resources/read",
        "tool": None,
        "uri": "file:///tmp/notes.md",
        "prompt": None,
    }


def test_uncorrelated_responses_pass_through_unfiltered(core):
    """Without a matching request the gateway must not guess — forward unchanged."""
    response = json.dumps(
        {"jsonrpc": "2.0", "id": 99, "result": {"tools": [{"name": "delete_file"}]}}
    )
    proxy = _proxy(core, server_lines=response + "\n")

    proxy.run()

    delivered = _messages(proxy.client_out)
    assert [t["name"] for t in delivered[0]["result"]["tools"]] == ["delete_file"]


def test_server_notifications_reach_the_client(core):
    notification = json.dumps(
        {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    )
    proxy = _proxy(core, server_lines=notification + "\n")

    proxy.run()

    assert (
        _messages(proxy.client_out)[0]["method"] == "notifications/tools/list_changed"
    )


# ── configuration ────────────────────────────────────────────────────


def test_load_config_reads_servers_and_settings(tmp_path):
    path = tmp_path / "minigate.yaml"
    path.write_text(
        """
client_id: claude-desktop
policy: policies/minigate.yaml
servers:
  notion:
    command: ["npx", "-y", "mcp-remote", "https://mcp.notion.com/mcp"]
  fs:
    command: ["fs-server"]
    policy: policies/fs.yaml
""",
        encoding="utf-8",
    )

    config = load_config(str(path))

    assert config.client_id == "claude-desktop"
    assert config.servers["notion"].command[0] == "npx"
    # Paths are resolved against the config file, not the working directory
    assert config.policy_for("notion") == str(tmp_path / "policies" / "minigate.yaml")
    assert config.policy_for("fs") == str(tmp_path / "policies" / "fs.yaml")


def test_policy_for_unknown_server_falls_back_to_the_default():
    """Constructed directly rather than loaded, so no path resolution applies."""
    config = GatewayConfig(policy="policies/minigate.yaml")

    assert config.policy_for("nonexistent") == "policies/minigate.yaml"


def test_missing_config_raises(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(str(tmp_path / "absent.yaml"))


def test_empty_server_command_is_rejected(tmp_path):
    path = tmp_path / "minigate.yaml"
    path.write_text("servers:\n  broken:\n    command: []\n", encoding="utf-8")

    with pytest.raises(ConfigError):
        load_config(str(path))


def test_defaults_are_safe():
    config = GatewayConfig()

    assert config.fail_closed is False
    assert config.injection.sensitivity == "LOW"  # stage-2 LLM must not sit inline
    assert config.injection.scan_tool_descriptions is True


def test_shipped_default_policy_is_an_allowlist():
    """The catch-all deny is what turns AgentGuard's default-ALLOW into an allowlist."""
    engine = PolicyEngine("policies/minigate.yaml")

    assert engine.rules[-1].action == "BLOCK"
    assert engine.rules[-1].id == "MG-999"


@pytest.mark.parametrize(
    ("tool", "expected"),
    [
        # Bare verbs, verb-with-suffix, and vendor-prefixed names all occur in the
        # wild. Regression: requiring a separator after the verb denied them all.
        ("notion.fetch", "ALLOW"),
        ("notion.search", "ALLOW"),
        ("notion.notion-fetch", "ALLOW"),
        ("notion.notion-search", "ALLOW"),
        ("fs.read_file", "ALLOW"),
        ("linear.list_issues", "ALLOW"),
        ("notion.delete-page", "BLOCK"),
        ("fs.delete_file", "BLOCK"),
        ("notion.delete", "BLOCK"),
        ("notion.notion-create-pages", "BLOCK"),
        ("notion.anything-unrecognised", "BLOCK"),
    ],
)
def test_shipped_policy_decisions_for_realistic_tool_names(tool, expected):
    from minigate.models import Direction, McpEvent

    server, _, name = tool.partition(".")
    event = McpEvent(
        server=server, method="tools/call", tool=name, direction=Direction.REQUEST
    )

    decision = PolicyEngine("policies/minigate.yaml").evaluate(event.to_agent_event())

    assert (
        decision.result == expected
    ), f"{tool} -> {decision.result} ({decision.matched_rule})"


# ── config path resolution ───────────────────────────────────────────


def test_relative_paths_resolve_against_the_config_file(tmp_path, monkeypatch):
    """MCP clients spawn servers from a working directory of their choosing — Claude
    Desktop uses "/" — so a relative path in the config must mean relative to the file.
    """
    (tmp_path / "policies").mkdir()
    (tmp_path / "policies" / "mine.yaml").write_text("rules: []", encoding="utf-8")
    cfg = tmp_path / "minigate.yaml"
    cfg.write_text(
        "policy: policies/mine.yaml\n"
        "database_url: minigate.db\n"
        "registry:\n  path: reg.yaml\n"
        "lineage:\n  store: taint.db\n"
        'servers:\n  fs:\n    command: ["fs-server"]\n    policy: policies/mine.yaml\n',
        encoding="utf-8",
    )

    monkeypatch.chdir("/")  # the failure only reproduces from another directory
    config = load_config(str(cfg))

    assert config.policy == str(tmp_path / "policies" / "mine.yaml")
    assert config.database_url == str(tmp_path / "minigate.db")
    assert config.registry.path == str(tmp_path / "reg.yaml")
    assert config.lineage.store == str(tmp_path / "taint.db")
    assert config.servers["fs"].policy == str(tmp_path / "policies" / "mine.yaml")
    # and the resolved policy actually loads
    PolicyEngine(config.policy_for("fs"))


def test_absolute_and_non_path_values_are_left_alone(tmp_path, monkeypatch):
    """A PostgreSQL URL is not a file, and ':memory:' is SQLite's in-process store."""
    cfg = tmp_path / "minigate.yaml"
    cfg.write_text(
        "database_url: postgresql://user@host/db\n"
        "lineage:\n  store: ':memory:'\n"
        f"policy: {tmp_path / 'abs.yaml'}\n"
        'servers:\n  fs:\n    command: ["fs-server"]\n',
        encoding="utf-8",
    )

    monkeypatch.chdir("/")
    config = load_config(str(cfg))

    assert config.database_url == "postgresql://user@host/db"
    assert config.lineage.store == ":memory:"
    assert config.policy == str(tmp_path / "abs.yaml")
