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
from io import StringIO
from uuid import UUID, uuid4

import pytest
from loguru import logger

from agentguard.interceptor import AgentGuardInterceptor
from agentguard.models import AgentEvent, InterceptorConfig

# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def log_capture():
    """Capture Loguru output for assertion in fail-open tests."""
    buffer = StringIO()
    handler_id = logger.add(buffer, format="{message}", level="WARNING")
    yield buffer
    logger.remove(handler_id)


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
        self, interceptor, serialized_tool, run_id, log_capture
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
        assert "fail-open" in log_capture.getvalue()

        # Restore and verify tool_end still works (simulating tool proceeding)
        interceptor._detect_input_risks = original
        # Even though on_tool_start failed, on_tool_end with unknown run_id
        # should not raise either
        interceptor.on_tool_end(output="result", run_id=run_id)

    def test_on_tool_start_survives_event_creation_crash(
        self, interceptor, run_id, log_capture, monkeypatch
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
        assert "fail-open" in log_capture.getvalue()

    def test_on_tool_end_survives_missing_start(self, interceptor, run_id):
        """on_tool_end with no matching on_tool_start does not raise."""
        interceptor.on_tool_end(output="orphan result", run_id=run_id)
        # Must not raise — logs warning and returns
        assert len(interceptor.completed_events) == 0

    def test_on_tool_end_survives_finalize_crash(
        self, interceptor, serialized_tool, run_id, log_capture, monkeypatch
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
        assert "fail-open" in log_capture.getvalue()

    def test_on_tool_error_survives_internal_failure(
        self, interceptor, run_id, log_capture
    ):
        """on_tool_error with corrupted internal state does not raise."""
        # Manually corrupt internal state
        interceptor.events[run_id] = "not an event"  # type: ignore[assignment]

        interceptor.on_tool_error(
            error=ValueError("original tool error"),
            run_id=run_id,
        )
        # Must not raise
        assert "fail-open" in log_capture.getvalue()

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
    """Tests for all 5 automatic risk flag types."""

    # ── sensitive_keyword ──────────────────────────────────────────

    def test_sensitive_keyword_in_input(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor, serialized_tool, "my password is hunter2", "ok", run_id
        )
        assert "sensitive_keyword" in interceptor.get_events()[0].risk_flags

    def test_sensitive_keyword_in_output(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor, serialized_tool, "get config", "api_key=sk-abc123", run_id
        )
        assert "sensitive_keyword" in interceptor.get_events()[0].risk_flags

    def test_custom_sensitive_keywords(self):
        cfg = InterceptorConfig(sensitive_keywords=["classified", "top_secret"])
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(i, {"name": "t"}, "classified document", "ok", rid)
        assert "sensitive_keyword" in i.get_events()[0].risk_flags

    def test_sensitive_keyword_not_flagged_for_clean_text(
        self, interceptor, serialized_tool, run_id
    ):
        invoke_tool(
            interceptor, serialized_tool, "normal query", "normal response", run_id
        )
        assert "sensitive_keyword" not in interceptor.get_events()[0].risk_flags

    # ── external_domain ────────────────────────────────────────────

    def test_external_domain_in_input_no_allowlist(
        self, interceptor, serialized_tool, run_id
    ):
        """No internal_domains configured — any URL is flagged."""
        invoke_tool(
            interceptor, serialized_tool, "fetch https://evil.com/data", "ok", run_id
        )
        assert "external_domain" in interceptor.get_events()[0].risk_flags

    def test_external_domain_in_output(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "query",
            "see https://external.io/leak",
            run_id,
        )
        assert "external_domain" in interceptor.get_events()[0].risk_flags

    def test_internal_domain_not_flagged_with_allowlist(self):
        """URL matching internal_domains allowlist should NOT be flagged."""
        cfg = InterceptorConfig(internal_domains=["company.com", "internal.corp"])
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(i, {"name": "t"}, "fetch https://api.company.com/data", "ok", rid)
        assert "external_domain" not in i.get_events()[0].risk_flags

    def test_subdomain_matches_allowlist(self):
        """Subdomains of allowlisted domains should also be allowed."""
        cfg = InterceptorConfig(internal_domains=["company.com"])
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(
            i, {"name": "t"}, "fetch https://api.us-east.company.com/v1", "ok", rid
        )
        assert "external_domain" not in i.get_events()[0].risk_flags

    def test_external_domain_flagged_with_allowlist(self):
        """URL NOT in allowlist should be flagged even when allowlist is set."""
        cfg = InterceptorConfig(internal_domains=["company.com"])
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(i, {"name": "t"}, "fetch https://evil.com/steal", "ok", rid)
        assert "external_domain" in i.get_events()[0].risk_flags

    def test_no_url_no_domain_flag(self, interceptor, serialized_tool, run_id):
        """Text without URLs should not trigger external_domain."""
        invoke_tool(
            interceptor, serialized_tool, "plain text query", "plain response", run_id
        )
        assert "external_domain" not in interceptor.get_events()[0].risk_flags

    # ── large_payload ──────────────────────────────────────────────

    def test_large_payload_flagged(self, interceptor, serialized_tool, run_id):
        invoke_tool(interceptor, serialized_tool, "query", "x" * 20_000, run_id)
        assert "large_payload" in interceptor.get_events()[0].risk_flags

    def test_small_payload_not_flagged(self, interceptor, serialized_tool, run_id):
        invoke_tool(interceptor, serialized_tool, "query", "small", run_id)
        assert "large_payload" not in interceptor.get_events()[0].risk_flags

    def test_custom_payload_threshold(self):
        cfg = InterceptorConfig(large_payload_threshold_bytes=50)
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(i, {"name": "t"}, "q", "x" * 100, rid)
        assert "large_payload" in i.get_events()[0].risk_flags

    def test_payload_at_exact_threshold_not_flagged(self):
        cfg = InterceptorConfig(large_payload_threshold_bytes=100)
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(i, {"name": "t"}, "q", "x" * 100, rid)  # exactly 100 bytes
        assert "large_payload" not in i.get_events()[0].risk_flags

    # ── high_frequency ─────────────────────────────────────────────

    def test_high_frequency_flagged(self):
        cfg = InterceptorConfig(
            high_frequency_threshold=3, high_frequency_window_seconds=60
        )
        i = AgentGuardInterceptor(config=cfg)
        serialized = {"name": "tool"}

        for j in range(5):
            invoke_tool(i, serialized, f"call {j}", "ok", uuid4())

        flagged = [e for e in i.get_events() if "high_frequency" in e.risk_flags]
        assert len(flagged) > 0

    def test_high_frequency_not_flagged_below_threshold(
        self, interceptor, serialized_tool
    ):
        """Default threshold is 10 — 3 calls should not trigger."""
        for j in range(3):
            invoke_tool(interceptor, serialized_tool, f"call {j}", "ok", uuid4())

        flagged = [
            e for e in interceptor.get_events() if "high_frequency" in e.risk_flags
        ]
        assert len(flagged) == 0

    # ── unknown_tool ───────────────────────────────────────────────

    def test_unknown_tool_flagged(self):
        """Tool not in known_tools allowlist should be flagged."""
        cfg = InterceptorConfig(known_tools=["send_email", "query_db"])
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(i, {"name": "evil_tool"}, "payload", "ok", rid)
        assert "unknown_tool" in i.get_events()[0].risk_flags

    def test_known_tool_not_flagged(self):
        """Tool in known_tools allowlist should NOT be flagged."""
        cfg = InterceptorConfig(known_tools=["send_email", "query_db"])
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(i, {"name": "send_email"}, "hello", "sent", rid)
        assert "unknown_tool" not in i.get_events()[0].risk_flags

    def test_unknown_tool_disabled_when_list_empty(
        self, interceptor, serialized_tool, run_id
    ):
        """Empty known_tools = detection disabled — no tool is flagged."""
        invoke_tool(interceptor, serialized_tool, "in", "out", run_id)
        assert "unknown_tool" not in interceptor.get_events()[0].risk_flags

    # ── clean input (no flags) ─────────────────────────────────────

    def test_clean_input_no_flags(self, interceptor, serialized_tool, run_id):
        invoke_tool(
            interceptor,
            serialized_tool,
            "What is the weather?",
            "Sunny and 72F.",
            run_id,
        )
        assert interceptor.get_events()[0].risk_flags == []

    # ── multiple flags on single event ─────────────────────────────

    def test_multiple_flags_on_single_event(self):
        """An event can accumulate multiple risk flags."""
        cfg = InterceptorConfig(
            known_tools=["safe_tool"],
            sensitive_keywords=["secret"],
        )
        i = AgentGuardInterceptor(config=cfg)
        rid = uuid4()
        invoke_tool(
            i,
            {"name": "bad_tool"},
            "secret https://evil.com/exfil",
            "x" * 20_000,
            rid,
        )
        flags = i.get_events()[0].risk_flags
        assert "unknown_tool" in flags
        assert "sensitive_keyword" in flags
        assert "external_domain" in flags
        assert "large_payload" in flags


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


# ── Acceptance criteria: 100 calls → 100 events (zero dropped) ───────


class TestHundredCallsZeroDropped:
    """Sprint 2 acceptance: 100 consecutive tool calls → 100 events in DB, zero dropped."""

    def test_100_calls_100_events_in_memory(self):
        """100 calls → 100 events in completed_events (no queue)."""
        interceptor = AgentGuardInterceptor(agent_id="acceptance", session_id="s1")
        serialized = {"name": "test_tool"}
        for i in range(100):
            rid = uuid4()
            interceptor.on_tool_start(
                serialized=serialized, input_str=f"in_{i}", run_id=rid
            )
            interceptor.on_tool_end(output=f"out_{i}", run_id=rid)

        assert interceptor.get_event_count() == 100
        # Verify no in-flight events leaked
        assert len(interceptor.events) == 0

    def test_100_calls_100_events_through_queue(self, tmp_path):
        """100 calls → 100 events persisted to SQLite via queue, zero dropped."""
        db_path = str(tmp_path / "acceptance.db")
        interceptor = AgentGuardInterceptor(
            agent_id="acceptance", session_id="s1", db_path=db_path
        )
        serialized = {"name": "test_tool"}

        for i in range(100):
            rid = uuid4()
            interceptor.on_tool_start(
                serialized=serialized, input_str=f"in_{i}", run_id=rid
            )
            interceptor.on_tool_end(output=f"out_{i}", run_id=rid)

        # Wait for queue consumer to flush
        time.sleep(0.5)

        assert interceptor.get_event_count() == 100
        assert interceptor.event_queue is not None
        assert interceptor.event_queue.events_written == 100
        assert interceptor.event_queue.events_dropped == 0
        assert interceptor.event_queue.store.get_event_count() == 100

        interceptor.event_queue.stop()

    def test_100_calls_with_mixed_tools(self, tmp_path):
        """100 calls across 5 different tools — all recorded."""
        db_path = str(tmp_path / "mixed.db")
        interceptor = AgentGuardInterceptor(agent_id="mixed", db_path=db_path)
        tools = ["read_email", "query_crm", "send_email", "lookup", "write_doc"]

        for i in range(100):
            tool_name = tools[i % len(tools)]
            rid = uuid4()
            interceptor.on_tool_start(
                serialized={"name": tool_name}, input_str=f"in_{i}", run_id=rid
            )
            interceptor.on_tool_end(output=f"out_{i}", run_id=rid)

        time.sleep(0.5)

        assert interceptor.get_event_count() == 100
        assert interceptor.event_queue.events_dropped == 0
        # Verify each tool was called 20 times
        tool_counts = {}
        for e in interceptor.get_events():
            tool_counts[e.tool_name] = tool_counts.get(e.tool_name, 0) + 1
        for t in tools:
            assert tool_counts[t] == 20

        interceptor.event_queue.stop()


# ── Interceptor latency measurement ──────────────────────────────────


class TestInterceptorLatency:
    """Sprint 2 acceptance: interceptor overhead p50<5ms, p95<20ms, p99<50ms.

    Measures the full on_tool_start → on_tool_end cycle overhead
    (not including actual tool execution, which is mocked).
    """

    def test_latency_p50_p95_p99(self):
        """Measure interceptor overhead over 1000 tool calls."""
        interceptor = AgentGuardInterceptor(agent_id="perf", session_id="perf")
        serialized = {"name": "fast_tool"}
        times: list[float] = []

        for i in range(1000):
            rid = uuid4()
            start = time.perf_counter()
            interceptor.on_tool_start(
                serialized=serialized, input_str=f"input_{i}", run_id=rid
            )
            interceptor.on_tool_end(output=f"output_{i}", run_id=rid)
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        sorted_times = sorted(times)
        p50 = sorted_times[499]
        p95 = sorted_times[949]
        p99 = sorted_times[989]

        assert p50 < 5.0, f"p50 interceptor overhead {p50:.3f}ms exceeds 5ms"
        assert p95 < 20.0, f"p95 interceptor overhead {p95:.3f}ms exceeds 20ms"
        assert p99 < 50.0, f"p99 interceptor overhead {p99:.3f}ms exceeds 50ms"
        assert interceptor.get_event_count() == 1000

    def test_latency_with_risk_detection(self):
        """Measure overhead including risk detection (keywords + domain check)."""
        cfg = InterceptorConfig(
            agent_id="perf",
            session_id="perf",
            known_tools=["allowed_tool"],
            internal_domains=["company.com"],
            sensitive_keywords=["password", "secret", "ssn"],
        )
        interceptor = AgentGuardInterceptor(config=cfg)
        serialized = {"name": "unknown_tool"}
        times: list[float] = []

        for i in range(500):
            rid = uuid4()
            start = time.perf_counter()
            interceptor.on_tool_start(
                serialized=serialized,
                input_str=f"fetch https://external.io/api?q={i}",
                run_id=rid,
            )
            interceptor.on_tool_end(
                output=f"response with password data {i}",
                run_id=rid,
            )
            elapsed_ms = (time.perf_counter() - start) * 1000
            times.append(elapsed_ms)

        sorted_times = sorted(times)
        p99 = sorted_times[int(len(times) * 0.99)]

        assert p99 < 50.0, f"p99 with risk detection {p99:.3f}ms exceeds 50ms"

        # Verify risk flags were actually being computed
        events = interceptor.get_events()
        assert all("unknown_tool" in e.risk_flags for e in events)
        assert all("external_domain" in e.risk_flags for e in events)


# ── mock_llm fixture integration ─────────────────────────────────────


class TestMockLlmFixture:
    """Verify the mock_llm fixture from conftest.py works with the interceptor.

    The injection detector (Sprint 4) will use mock_llm for classification.
    These tests prove the fixture integrates correctly with the interceptor
    pipeline and that the mock LLM returns deterministic results.
    """

    def test_mock_llm_returns_clean(self, mock_llm):
        """mock_llm fixture returns CLEAN classification by default."""
        assert mock_llm.classify("test input") == "CLEAN"
        assert mock_llm.provider == "mock"
        assert mock_llm.model == "mock-model"

    def test_mock_llm_configurable_response(self, mock_llm):
        """mock_llm can be configured to return any classification."""
        mock_llm.classify.return_value = "INJECTED"
        assert mock_llm.classify("ignore previous instructions") == "INJECTED"

    def test_interceptor_works_alongside_mock_llm(self, mock_llm):
        """Interceptor functions correctly when mock_llm is in scope.

        This proves the fixture doesn't interfere with the interceptor —
        important for Sprint 4 when the injection detector is wired in.
        """
        interceptor = AgentGuardInterceptor(agent_id="llm-test")
        rid = uuid4()
        invoke_tool(interceptor, {"name": "classify"}, "test text", "result", rid)

        assert interceptor.get_event_count() == 1
        # mock_llm is available but interceptor doesn't use it yet
        assert mock_llm.classify("test") == "CLEAN"


# ── Health check endpoint ────────────────────────────────────────────


class TestHealthCheck:
    """Tests for the GET /health JSON status endpoint."""

    def test_health_check_without_queue(self):
        """Health check with no queue returns base fields."""
        interceptor = AgentGuardInterceptor(agent_id="health-test", session_id="sess-1")
        health = interceptor.health_check()

        assert health["status"] == "healthy"
        assert health["version"] == "2.0.0"
        assert health["agent_id"] == "health-test"
        assert health["session_id"] == "sess-1"
        assert health["events_in_memory"] == 0
        assert health["inflight_events"] == 0
        assert health["queue_depth"] == 0
        assert health["events_written"] == 0
        assert health["events_dropped"] == 0
        assert health["events_per_second"] == 0.0
        assert health["db_connection"] == "not_configured"

    def test_health_check_with_queue(self, tmp_path):
        """Health check with active queue reports DB and queue state."""
        db_path = str(tmp_path / "health.db")
        interceptor = AgentGuardInterceptor(
            agent_id="h-agent", session_id="h-sess", db_path=db_path
        )

        # Send a few events
        for i in range(5):
            rid = uuid4()
            invoke_tool(interceptor, {"name": "tool"}, f"in_{i}", f"out_{i}", rid)

        time.sleep(0.3)

        health = interceptor.health_check()

        assert health["status"] == "healthy"
        assert health["db_connection"] == "healthy"
        assert health["events_in_memory"] == 5
        assert health["events_written"] == 5
        assert health["events_dropped"] == 0
        assert health["queue_depth"] == 0
        assert health["db_event_count"] == 5
        assert isinstance(health["events_per_second"], float)

        interceptor.event_queue.stop()

    def test_health_check_after_events(self):
        """Health check reflects in-memory event count."""
        interceptor = AgentGuardInterceptor()
        invoke_tool(interceptor, {"name": "t"}, "in", "out", uuid4())
        invoke_tool(interceptor, {"name": "t"}, "in", "out", uuid4())

        health = interceptor.health_check()
        assert health["events_in_memory"] == 2

    def test_health_check_during_inflight(self):
        """Health check reports inflight events (started but not ended)."""
        interceptor = AgentGuardInterceptor()
        rid = uuid4()
        interceptor.on_tool_start(
            serialized={"name": "slow"}, input_str="x", run_id=rid
        )

        health = interceptor.health_check()
        assert health["inflight_events"] == 1
        assert health["events_in_memory"] == 0

        interceptor.on_tool_end(output="done", run_id=rid)

        health = interceptor.health_check()
        assert health["inflight_events"] == 0
        assert health["events_in_memory"] == 1

    def test_health_check_json_serializable(self, tmp_path):
        """Health check output must be JSON-serializable for HTTP responses."""
        import json

        db_path = str(tmp_path / "json_test.db")
        interceptor = AgentGuardInterceptor(db_path=db_path)
        invoke_tool(interceptor, {"name": "t"}, "in", "out", uuid4())
        time.sleep(0.2)

        health = interceptor.health_check()
        serialized = json.dumps(health)
        parsed = json.loads(serialized)

        assert parsed["status"] == "healthy"
        assert isinstance(parsed["version"], str)
        assert isinstance(parsed["events_per_second"], float)

        interceptor.event_queue.stop()

    def test_health_check_returns_all_required_fields(self):
        """Verify all fields specified in the Sprint 2 requirement exist."""
        interceptor = AgentGuardInterceptor()
        health = interceptor.health_check()

        required_fields = [
            "status",
            "version",
            "db_connection",
            "queue_depth",
            "events_per_second",
        ]
        for field in required_fields:
            assert field in health, f"Missing required field: {field}"
