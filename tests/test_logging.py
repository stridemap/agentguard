"""Tests for Loguru structured JSON logging in the AgentGuard interceptor.

Verifies:
- on_tool_start emits structured JSON log with all AgentEvent fields
- on_tool_end emits structured JSON log with latency and output hash
- on_tool_error emits structured JSON log with error details
- Fail-open warnings are logged as structured JSON
- No print() statements anywhere in the codebase
- Log entries contain correct phase, event_id, agent_id, tool_name, etc.
"""

from __future__ import annotations

import json
from io import StringIO
from uuid import uuid4

import pytest
from loguru import logger

from agentguard.interceptor import AgentGuardInterceptor
from agentguard.models import AgentEvent

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def log_sink():
    """Capture Loguru output into a StringIO buffer for assertion.

    Adds a temporary Loguru sink that captures serialized JSON output,
    and removes it after the test.
    """
    buffer = StringIO()
    handler_id = logger.add(
        buffer,
        format="{message}",
        serialize=True,
        level="DEBUG",
        filter="agentguard",
    )
    yield buffer
    logger.remove(handler_id)


@pytest.fixture()
def interceptor():
    """Return a fresh interceptor."""
    return AgentGuardInterceptor(
        agent_id="log-test-agent", session_id="log-test-session"
    )


@pytest.fixture()
def run_id():
    return uuid4()


@pytest.fixture()
def serialized_tool():
    return {"name": "send_email"}


def parse_log_entries(buffer: StringIO) -> list[dict]:
    """Parse all JSON log entries from the buffer."""
    entries = []
    for line in buffer.getvalue().strip().split("\n"):
        if line.strip():
            entries.append(json.loads(line))
    return entries


# ── Structured log output tests ──────────────────────────────────────


class TestStructuredLogging:
    """Verify Loguru emits structured JSON with all AgentEvent fields."""

    def test_on_tool_start_emits_json_log(
        self, interceptor, serialized_tool, run_id, log_sink
    ):
        """on_tool_start should produce a JSON log with phase=tool_start."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="hello world",
            run_id=run_id,
        )

        entries = parse_log_entries(log_sink)
        assert len(entries) >= 1

        entry = entries[0]
        extra = entry["record"]["extra"]
        assert extra["phase"] == "tool_start"
        assert extra["tool_name"] == "send_email"
        assert extra["agent_id"] == "log-test-agent"
        assert extra["session_id"] == "log-test-session"
        assert extra["run_id"] == str(run_id)
        assert extra["input_hash"] == AgentEvent.compute_hash("hello world")
        assert extra["policy_result"] == "PENDING"
        assert extra["completed"] is False
        assert isinstance(extra["event_id"], str)
        assert isinstance(extra["timestamp"], str)

    def test_on_tool_end_emits_json_log_with_latency(
        self, interceptor, serialized_tool, run_id, log_sink
    ):
        """on_tool_end should produce a JSON log with phase=tool_end, latency, and output hash."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="query",
            run_id=run_id,
        )
        interceptor.on_tool_end(
            output="result data",
            run_id=run_id,
        )

        entries = parse_log_entries(log_sink)
        # Should have 2 entries: tool_start + tool_end
        assert len(entries) >= 2

        end_entry = entries[-1]
        extra = end_entry["record"]["extra"]
        assert extra["phase"] == "tool_end"
        assert extra["tool_name"] == "send_email"
        assert extra["output_hash"] == AgentEvent.compute_hash("result data")
        assert extra["policy_result"] == "ALLOW"
        assert extra["completed"] is True
        assert isinstance(extra["latency_ms"], float)
        assert extra["latency_ms"] >= 0

    def test_on_tool_error_emits_json_log(
        self, interceptor, serialized_tool, run_id, log_sink
    ):
        """on_tool_error should produce a JSON log with phase=tool_error."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="bad input",
            run_id=run_id,
        )
        interceptor.on_tool_error(
            error=ValueError("something failed"),
            run_id=run_id,
        )

        entries = parse_log_entries(log_sink)
        assert len(entries) >= 2

        error_entry = entries[-1]
        extra = error_entry["record"]["extra"]
        assert extra["phase"] == "tool_error"
        assert extra["completed"] is True
        assert (
            "TOOL_ERROR" in extra.get("output_hash", "")
            or error_entry["record"]["level"]["name"] == "INFO"
        )

    def test_risk_flags_included_in_log(
        self, interceptor, serialized_tool, run_id, log_sink
    ):
        """Risk flags should appear in the structured JSON log."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="my password is hunter2",
            run_id=run_id,
        )

        entries = parse_log_entries(log_sink)
        extra = entries[0]["record"]["extra"]
        assert "sensitive_keyword" in extra["risk_flags"]

    def test_log_contains_event_id_as_uuid(
        self, interceptor, serialized_tool, run_id, log_sink
    ):
        """event_id in the log should be a valid UUID string."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="test",
            run_id=run_id,
        )

        entries = parse_log_entries(log_sink)
        event_id = entries[0]["record"]["extra"]["event_id"]
        # UUID format: 8-4-4-4-12
        assert len(event_id) == 36
        assert event_id.count("-") == 4

    def test_log_message_contains_tool_and_agent(
        self, interceptor, serialized_tool, run_id, log_sink
    ):
        """The log message string should contain tool name and agent ID."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="test",
            run_id=run_id,
        )

        entries = parse_log_entries(log_sink)
        message = entries[0]["text"]
        assert "send_email" in message
        assert "log-test-agent" in message


# ── Fail-open logging tests ──────────────────────────────────────────


class TestFailOpenLogging:
    """Verify fail-open errors are logged as structured JSON warnings."""

    def test_fail_open_logs_warning_with_error_detail(
        self, interceptor, run_id, log_sink
    ):
        """When on_tool_start fails, the warning should be structured JSON."""
        interceptor.on_tool_start(
            serialized=None,  # type: ignore[arg-type]
            input_str="test",
            run_id=run_id,
        )

        entries = parse_log_entries(log_sink)
        assert len(entries) >= 1

        warning_entry = entries[-1]
        assert warning_entry["record"]["level"]["name"] == "WARNING"
        assert "fail-open" in warning_entry["text"]


# ── No print() statements ───────────────────────────────────────────


class TestNoPrintStatements:
    """Verify no print() calls exist in the agentguard package.

    Uses the AST to detect actual print() function calls, ignoring
    mentions of 'print' in docstrings, comments, and string literals.
    """

    @staticmethod
    def _find_print_calls(module) -> list[int]:
        """Return line numbers of print() calls in a module's source."""
        import ast
        import inspect

        source = inspect.getsource(module)
        tree = ast.parse(source)
        lines = []
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "print"
            ):
                lines.append(node.lineno)
        return lines

    def test_no_print_in_interceptor(self):
        import agentguard.interceptor as mod

        lines = self._find_print_calls(mod)
        assert (
            lines == []
        ), f"Found print() calls in agentguard/interceptor.py at lines {lines}"

    def test_no_print_in_models(self):
        import agentguard.models as mod

        lines = self._find_print_calls(mod)
        assert (
            lines == []
        ), f"Found print() calls in agentguard/models.py at lines {lines}"

    def test_no_print_in_logging_module(self):
        import agentguard.logging as mod

        lines = self._find_print_calls(mod)
        assert (
            lines == []
        ), f"Found print() calls in agentguard/logging.py at lines {lines}"
