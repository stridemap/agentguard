"""Structured JSON logging for MiniGate via Loguru.

CRITICAL: MiniGate speaks the MCP protocol over stdout. Anything written to stdout
that is not a JSON-RPC message corrupts the stream and breaks the client. Every log
sink here targets stderr, and no MiniGate module may use print().

AgentGuard installs its own stderr sink filtered to the "agentguard" namespace, so
this adds a separate sink for the "minigate" namespace rather than reusing it.
"""

from __future__ import annotations

import os
import sys

from loguru import logger as _loguru_logger

_LEVEL = os.getenv("MINIGATE_LOG_LEVEL", "INFO").upper()

_loguru_logger.add(
    sys.stderr,
    format="{message}",
    serialize=True,
    level=_LEVEL,
    filter="minigate",
)

logger = _loguru_logger.bind(module="minigate")
