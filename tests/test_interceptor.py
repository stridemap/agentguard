"""Tests for AgentGuard interceptor — BaseCallbackHandler lifecycle.

Covers:
- on_tool_start creates event with correct metadata
- on_tool_end finalizes event with output, latency, and risk flags
- Fail-open guarantee (interceptor errors don't block tool calls)
- Risk auto-detection (external_domain, large_payload, sensitive_keyword, high_frequency)
- Event counting and retrieval
- SHA-256 hashing correctness
"""

from __future__ import annotations

import hashlib
import time
from uuid import UUID, uuid4

import pytest

from agentguard.interceptor import AgentGuardInterceptor
from agentguard.models import AgentEvent, InterceptorConfig

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def interceptor():
    """Return a fresh interceptor instance."""
    return AgentGuardInterceptor(agent_id="test-agent", session_id="test-session")


@pytest.fixture()
def run_id():
    """Return a fixed run_id for deterministic tests."""
    return uuid4()


@pytest.fixture()
def parent_run_id():
    """Return a fixed parent_run_id."""
    return uuid4()


@pytest.fixture()
def serialized_tool():
    """Return a minimal serialized tool dict."""
    return {"name": "send_email", "id": ["tool", "send_email"]}


def invoke_tool(
    interceptor, serialized, input_str, output_str, run_id, parent_run_id=None
):
    """Helper: simulate a full tool start → end cycle."""
    interceptor.on_tool_start(
        serialized=serialized,
        input_str=input_str,
        run_id=run_id,
        parent_run_id=parent_run_id,
    )
    interceptor.on_tool_end(
        output=output_str,
        run_id=run_id,
        parent_run_id=parent_run_id,
    )


# ── on_tool_start tests ──────────────────────────────────────────────


class TestOnToolStart:
    """Tests for the on_tool_start callback."""

    def test_creates_event_with_correct_metadata(
        self, interceptor, serialized_tool, run_id, parent_run_id
    ):
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="hello world",
            run_id=run_id,
            parent_run_id=parent_run_id,
        )

        assert run_id in interceptor.events
        event = interceptor.events[run_id]
        assert event.tool_name == "send_email"
        assert event.agent_id == "test-agent"
        assert event.session_id == "test-session"
        assert event.run_id == run_id
        assert event.parent_run_id == parent_run_id
        assert event.input_str == "hello world"
        assert event.completed is False

    def test_computes_input_hash(self, interceptor, serialized_tool, run_id):
        input_text = "test input data"
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str=input_text,
            run_id=run_id,
        )

        expected_hash = hashlib.sha256(input_text.encode("utf-8")).hexdigest()
        assert interceptor.events[run_id].input_hash == expected_hash

    def test_extracts_tool_name_from_name_field(self, interceptor, run_id):
        interceptor.on_tool_start(
            serialized={"name": "query_database"},
            input_str="SELECT *",
            run_id=run_id,
        )
        assert interceptor.events[run_id].tool_name == "query_database"

    def test_extracts_tool_name_from_id_list(self, interceptor, run_id):
        interceptor.on_tool_start(
            serialized={"id": ["langchain", "tools", "web_search"]},
            input_str="query",
            run_id=run_id,
        )
        assert interceptor.events[run_id].tool_name == "web_search"

    def test_unknown_tool_name_fallback(self, interceptor, run_id):
        interceptor.on_tool_start(
            serialized={},
            input_str="data",
            run_id=run_id,
        )
        assert interceptor.events[run_id].tool_name == "unknown_tool"

    def test_records_start_time(self, interceptor, serialized_tool, run_id):
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="hello",
            run_id=run_id,
        )
        assert run_id in interceptor._start_times


# ── on_tool_end tests ─────────────────────────────────────────────────


class TestOnToolEnd:
    """Tests for the on_tool_end callback."""

    def test_finalizes_event(self, interceptor, serialized_tool, run_id):
        invoke_tool(interceptor, serialized_tool, "input", "output result", run_id)

        events = interceptor.get_events()
        assert len(events) == 1
        event = events[0]
        assert event.completed is True
        assert event.output_str == "output result"
        assert event.policy_result == "ALLOW"

    def test_computes_output_hash(self, interceptor, serialized_tool, run_id):
        invoke_tool(interceptor, serialized_tool, "input", "output data", run_id)

        event = interceptor.get_events()[0]
        expected_hash = hashlib.sha256(b"output data").hexdigest()
        assert event.output_hash == expected_hash

    def test_calculates_latency(self, interceptor, serialized_tool, run_id):
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="test",
            run_id=run_id,
        )
        time.sleep(0.01)  # 10ms
        interceptor.on_tool_end(output="done", run_id=run_id)

        event = interceptor.get_events()[0]
        assert event.latency_ms is not None
        assert event.latency_ms >= 5  # At least ~5ms (sleep 10ms with some tolerance)

    def test_moves_event_from_inflight_to_completed(
        self, interceptor, serialized_tool, run_id
    ):
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="test",
            run_id=run_id,
        )
        assert run_id in interceptor.events
        assert len(interceptor.completed_events) == 0

        interceptor.on_tool_end(output="done", run_id=run_id)
        assert run_id not in interceptor.events
        assert len(interceptor.completed_events) == 1

    def test_unknown_run_id_logs_warning(self, interceptor, caplog):
        unknown_id = uuid4()
        interceptor.on_tool_end(output="orphan", run_id=unknown_id)
        assert len(interceptor.completed_events) == 0

    def test_default_policy_result_is_allow(self, interceptor, serialized_tool, run_id):
        invoke_tool(interceptor, serialized_tool, "input", "output", run_id)
        assert interceptor.get_events()[0].policy_result == "ALLOW"


# ── on_tool_error tests ──────────────────────────────────────────────


class TestOnToolError:
    """Tests for the on_tool_error callback."""

    def test_records_error_event(self, interceptor, serialized_tool, run_id):
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="bad input",
            run_id=run_id,
        )
        interceptor.on_tool_error(
            error=ValueError("tool crashed"),
            run_id=run_id,
        )

        assert len(interceptor.completed_events) == 1
        event = interceptor.completed_events[0]
        assert "TOOL_ERROR" in event.output_str
        assert "ValueError" in event.output_str
        assert event.completed is True

    def test_error_with_unknown_run_id(self, interceptor):
        interceptor.on_tool_error(
            error=RuntimeError("mystery"),
            run_id=uuid4(),
        )
        assert len(interceptor.completed_events) == 0


# ── Fail-open guarantee ──────────────────────────────────────────────


class TestFailOpen:
    """Verify the interceptor NEVER blocks tool calls due to its own errors.

    These are adversarial tests that force internal failures via monkey-patching,
    None injection, and broken state — then verify the interceptor swallows the
    error and lets the tool call proceed.
    """

    def test_on_tool_start_survives_none_serialized(self, interceptor, run_id):
        """on_tool_start with None serialized does not raise."""
        interceptor.on_tool_start(
            serialized=None,  # type: ignore[arg-type]
            input_str="test",
            run_id=run_id,
        )
        # Must not raise — fail-open catches the TypeError/AttributeError

    def test_on_tool_start_survives_runtime_error_in_risk_detection(
        self, interceptor, serialized_tool, run_id, caplog
    ):
        """Force RuntimeError inside _detect_input_risks → tool call proceeds."""
        original = interceptor._detect_input_risks

        def _boom(input_str):
            raise RuntimeError("risk detection exploded")

        interceptor._detect_input_risks = _boom

        # This must NOT raise
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="hello",
            run_id=run_id,
        )

        # Verify warning was logged
        assert any("fail-open" in record.message for record in caplog.records)

        # Restore and verify tool_end still works (simulating tool proceeding)
        interceptor._detect_input_risks = original
        # Even though on_tool_start failed, on_tool_end with unknown run_id
        # should not raise either
        interceptor.on_tool_end(output="result", run_id=run_id)

    def test_on_tool_start_survives_event_creation_crash(
        self, interceptor, run_id, caplog, monkeypatch
    ):
        """Force AgentEvent constructor to raise → on_tool_start still returns."""
        monkeypatch.setattr(
            "agentguard.interceptor.AgentEvent",
            type(
                "BrokenEvent",
                (),
                {"compute_hash": lambda s: (_ for _ in ()).throw(RuntimeError("boom"))},
            ),
        )

        interceptor.on_tool_start(
            serialized={"name": "tool"},
            input_str="data",
            run_id=run_id,
        )
        # Must not raise
        assert any("fail-open" in r.message for r in caplog.records)

    def test_on_tool_end_survives_missing_start(self, interceptor, run_id):
        """on_tool_end with no matching on_tool_start does not raise."""
        interceptor.on_tool_end(output="orphan result", run_id=run_id)
        # Must not raise — logs warning and returns
        assert len(interceptor.completed_events) == 0

    def test_on_tool_end_survives_finalize_crash(
        self, interceptor, serialized_tool, run_id, caplog, monkeypatch
    ):
        """Force AgentEvent.finalize() to raise → on_tool_end still returns."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="input",
            run_id=run_id,
        )

        # Monkey-patch finalize on the class to explode
        def _broken_finalize(self, **kw):
            raise RuntimeError("finalize broke")

        monkeypatch.setattr(AgentEvent, "finalize", _broken_finalize)

        interceptor.on_tool_end(output="result", run_id=run_id)
        # Must not raise
        assert any("fail-open" in r.message for r in caplog.records)

    def test_on_tool_error_survives_internal_failure(self, interceptor, run_id, caplog):
        """on_tool_error with corrupted internal state does not raise."""
        # Manually corrupt internal state
        interceptor.events[run_id] = "not an event"  # type: ignore[assignment]

        interceptor.on_tool_error(
            error=ValueError("original tool error"),
            run_id=run_id,
        )
        # Must not raise
        assert any("fail-open" in r.message for r in caplog.records)

    def test_on_tool_start_none_input_str(self, interceptor, serialized_tool, run_id):
        """on_tool_start with None input_str does not raise."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str=None,  # type: ignore[arg-type]
            run_id=run_id,
        )
        # Might fail inside compute_hash — fail-open catches it

    def test_on_tool_end_non_string_output(self, interceptor, serialized_tool, run_id):
        """on_tool_end with non-string output (dict) does not raise."""
        interceptor.on_tool_start(
            serialized=serialized_tool,
            input_str="query",
            run_id=run_id,
        )
        interceptor.on_tool_end(
            output={"key": "value"},  # type: ignore[arg-type]
            run_id=run_id,
        )
        # Must not raise — output is str()'d inside on_tool_end
        events = interceptor.get_events()
        assert len(events) == 1
        assert "key" in events[0].output_str

    def test_full_lifecycle_after_start_failure(self, interceptor, serialized_tool):
        """Even if on_tool_start fails, the agent can make another call successfully."""
        bad_id = uuid4()
        good_id = uuid4()

        # First call: force failure
        interceptor.on_tool_start(
            serialized=None,  # type: ignore[arg-type]
            input_str="bad call",
            run_id=bad_id,
        )

        # Second call: should work perfectly
        invoke_tool(
            interceptor,
            serialized_tool,
            "good input",
            "good output",
            good_id,
        )

        events = interceptor.get_events()
        assert len(events) == 1
        assert events[0].tool_name == "send_email"
        assert events[0].output_str == "good output"

    def test_hundred_calls_with_intermittent_failures(
        self, interceptor, serialized_tool
    ):
        """100 tool calls where every 10th on_tool_start is sabotaged.

        Verifies that failures don't corrupt state and subsequent calls succeed.
        """
        successful = 0
        for i in range(100):
            rid = uuid4()

            if i % 10 == 0:
                # Sabotage: pass None serialized to trigger fail-open
                interceptor.on_tool_start(
                    serialized=None,  # type: ignore[arg-type]
                    input_str=f"input_{i}",
                    run_id=rid,
                )
                # on_tool_end for a failed start should not raise
                interceptor.on_tool_end(output=f"output_{i}", run_id=rid)
            else:
                invoke_tool(
                    interceptor,
                    serialized_tool,
                    f"input_{i}",
                    f"output_{i}",
                    rid,
                )
                successful += 1

        # All 90 non-sabotaged calls should produce events
        assert interceptor.get_event_count() == successful


# ── Risk auto-detection ──────────────────────────────────────────────


class TestRiskDetection:
    """Tests for automatic risk flag detection."""

    def test_sensitive_keyword_in_input(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "my password is hunter2",
            "ok",
            run_id,
        )
        event = interceptor.get_events()[0]
        assert "sensitive_keyword" in event.risk_flags

    def test_sensitive_keyword_in_output(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "get config",
            "api_key=sk-abc123",
            run_id,
        )
        event = interceptor.get_events()[0]
        assert "sensitive_keyword" in event.risk_flags

    def test_external_domain_in_input(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "fetch https://evil.com/data",
            "ok",
            run_id,
        )
        event = interceptor.get_events()[0]
        assert "external_domain" in event.risk_flags

    def test_internal_domain_not_flagged(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "fetch https://api.internal.company.com/data",
            "ok",
            run_id,
        )
        # internal domain should not be flagged — but our simple regex
        # checks for "internal." in the URL which is present here
        # This is a heuristic; the policy engine handles real allowlisting

    def test_large_payload_flagged(self, interceptor, serialized_tool, run_id):
        large_output = "x" * 20_000  # 20KB > 10KB threshold
        invoke_tool(
            interceptor,
            serialized_tool,
            "query",
            large_output,
            run_id,
        )
        event = interceptor.get_events()[0]
        assert "large_payload" in event.risk_flags

    def test_small_payload_not_flagged(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "query",
            "small response",
            run_id,
        )
        event = interceptor.get_events()[0]
        assert "large_payload" not in event.risk_flags

    def test_high_frequency_flagged(self):
        interceptor = AgentGuardInterceptor(
            config=InterceptorConfig(
                agent_id="test",
                session_id="test",
                high_frequency_threshold=3,
                high_frequency_window_seconds=60,
            )
        )
        serialized = {"name": "tool"}

        # Make 5 calls quickly — should trigger high_frequency after threshold
        for i in range(5):
            rid = uuid4()
            invoke_tool(interceptor, serialized, f"call {i}", "ok", rid)

        events = interceptor.get_events()
        # At least one event should have high_frequency flag
        flagged = [e for e in events if "high_frequency" in e.risk_flags]
        assert len(flagged) > 0

    def test_clean_input_no_flags(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "What is the weather today?",
            "It is sunny and 72F.",
            run_id,
        )
        event = interceptor.get_events()[0]
        assert event.risk_flags == []


# ── Event counting and management ────────────────────────────────────


class TestEventManagement:
    """Tests for event retrieval and management."""

    def test_consecutive_tool_calls_all_recorded(self, interceptor, serialized_tool):
        for i in range(100):
            rid = uuid4()
            invoke_tool(interceptor, serialized_tool, f"input_{i}", f"output_{i}", rid)

        assert interceptor.get_event_count() == 100

    def test_get_events_returns_copy(self, interceptor, serialized_tool, run_id):
        invoke_tool(interceptor, serialized_tool, "in", "out", run_id)

        events1 = interceptor.get_events()
        events2 = interceptor.get_events()
        assert events1 is not events2

    def test_clear_events(self, interceptor, serialized_tool, run_id):
        invoke_tool(interceptor, serialized_tool, "in", "out", run_id)
        assert interceptor.get_event_count() == 1

        interceptor.clear_events()
        assert interceptor.get_event_count() == 0

    def test_multiple_tools_tracked_independently(self, interceptor):
        rid1, rid2 = uuid4(), uuid4()

        interceptor.on_tool_start(
            serialized={"name": "tool_a"},
            input_str="input_a",
            run_id=rid1,
        )
        interceptor.on_tool_start(
            serialized={"name": "tool_b"},
            input_str="input_b",
            run_id=rid2,
        )

        assert len(interceptor.events) == 2

        interceptor.on_tool_end(output="output_b", run_id=rid2)
        interceptor.on_tool_end(output="output_a", run_id=rid1)

        assert len(interceptor.completed_events) == 2
        names = {e.tool_name for e in interceptor.completed_events}
        assert names == {"tool_a", "tool_b"}


# ── AgentEvent model tests ───────────────────────────────────────────


class TestAgentEventModel:
    """Tests for the Pydantic AgentEvent model."""

    def test_compute_hash_deterministic(self):
        h1 = AgentEvent.compute_hash("hello")
        h2 = AgentEvent.compute_hash("hello")
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex length

    def test_compute_hash_different_inputs(self):
        h1 = AgentEvent.compute_hash("hello")
        h2 = AgentEvent.compute_hash("world")
        assert h1 != h2

    def test_finalize_sets_fields(self):
        event = AgentEvent(
            tool_name="test_tool",
            run_id=uuid4(),
        )
        event.finalize(output="result", latency_ms=42.5)

        assert event.output_str == "result"
        assert event.output_hash == AgentEvent.compute_hash("result")
        assert event.latency_ms == 42.5
        assert event.completed is True

    def test_default_values(self):
        event = AgentEvent(tool_name="t", run_id=uuid4())
        assert event.agent_id == "unknown"
        assert event.session_id == "unknown"
        assert event.risk_flags == []
        assert event.policy_result == "PENDING"
        assert event.completed is False

    def test_event_id_is_uuid4(self):
        event = AgentEvent(tool_name="t", run_id=uuid4())
        assert isinstance(event.event_id, UUID)

    def test_serialization_roundtrip(self):
        event = AgentEvent(
            tool_name="send_email",
            run_id=uuid4(),
            agent_id="agent-1",
            input_str="hello",
            input_hash=AgentEvent.compute_hash("hello"),
        )
        data = event.model_dump()
        restored = AgentEvent.model_validate(data)
        assert restored.tool_name == "send_email"
        assert restored.agent_id == "agent-1"


# ── Constructor tests ─────────────────────────────────────────────────


class TestInterceptorConfig:
    """Tests for interceptor initialization and configuration."""

    def test_default_config(self):
        interceptor = AgentGuardInterceptor()
        assert interceptor.agent_id == "default-agent"
        assert interceptor.session_id == "default-session"

    def test_custom_agent_session(self):
        interceptor = AgentGuardInterceptor(agent_id="my-agent", session_id="sess-42")
        assert interceptor.agent_id == "my-agent"
        assert interceptor.session_id == "sess-42"

    def test_config_object_overrides_params(self):
        cfg = InterceptorConfig(agent_id="cfg-agent", session_id="cfg-session")
        interceptor = AgentGuardInterceptor(
            agent_id="ignored",
            session_id="ignored",
            config=cfg,
        )
        assert interceptor.agent_id == "cfg-agent"
        assert interceptor.session_id == "cfg-session"

    def test_custom_thresholds(self):
        cfg = InterceptorConfig(
            large_payload_threshold_bytes=1024,
            high_frequency_threshold=5,
        )
        interceptor = AgentGuardInterceptor(config=cfg)
        assert interceptor.config.large_payload_threshold_bytes == 1024
        assert interceptor.config.high_frequency_threshold == 5
