"""Structured JSON logging for AgentGuard via Loguru.

Provides a pre-configured logger that outputs structured JSON to stderr.
All AgentGuard modules should import `logger` from this module instead
of using stdlib logging or print().

Usage:
    from agentguard.logging import logger

    logger.info("event happened", tool_name="send_email", agent_id="agent-1")
"""

from __future__ import annotations

import sys

from loguru import logger as _loguru_logger

# Remove default Loguru handler (plain text to stderr)
_loguru_logger.remove()

# Add structured JSON handler
_loguru_logger.add(
    sys.stderr,
    format="{message}",
    serialize=True,
    level="DEBUG",
    filter="agentguard",
)

# Re-export as module-level logger bound to the agentguard namespace
logger = _loguru_logger.bind(module="agentguard")
