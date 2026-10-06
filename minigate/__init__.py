"""MiniGate — an MCP protocol gateway that governs what AI agents may do.

MiniGate sits between an MCP client (Claude Desktop, Cursor, Claude Code, or any
agent using an MCP client library) and the MCP servers it connects to. It filters
the tool list the model is allowed to see, blocks disallowed tool calls before they
reach an external system, scans tool results before they re-enter model context,
and records every decision to a tamper-evident audit chain.

Governance happens at the MCP protocol layer, which makes it client- and
framework-agnostic: no SDK adoption, no code change in the agent, no API keys and
no TLS interception. See docs/adr/001-no-model-channel-interception.md.

Usage (as a stdio shim in claude_desktop_config.json):

    minigate stdio --server-name notion -- npx -y mcp-remote https://mcp.notion.com/mcp
"""

from __future__ import annotations

from minigate.config import GatewayConfig, ServerConfig, load_config
from minigate.core import GatewayCore
from minigate.models import Direction, McpEvent

__version__ = "0.1.0"

__all__ = [
    "Direction",
    "GatewayConfig",
    "GatewayCore",
    "McpEvent",
    "ServerConfig",
    "__version__",
    "load_config",
]
