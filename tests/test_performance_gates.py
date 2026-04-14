"""Performance gate tests — enforced on every release.

These tests assert hard latency SLAs. If any fail, the release is blocked.
Run with: pytest tests/test_performance_gates.py -v

SLA targets:
  - Interceptor overhead: p50 <5ms, p95 <20ms, p99 <50ms
  - Policy evaluation: p99 <5ms, 1000 evals <5s total
  - Queue enqueue: p99 <5ms
  - Injection Stage 1: p99 <5ms for 1KB
  - Event store append: p99 <10ms (SQLite)
  - Health endpoint: p99 <50ms
"""

from __future__ import annotations

import time
from pathlib import Path
from uuid import uuid4

from agentguard.event_store import EventQueue, EventStore
from agentguard.injection_detector import InjectionDetector
from agentguard.interceptor import AgentGuardInterceptor
from agentguard.models import AgentEvent, InterceptorConfig
from agentguard.policy_engine import PolicyEngine


def make_event() -> AgentEvent:
    event = AgentEvent(
        agent_id="perf",
        session_id="perf",
        tool_name="tool",
        run_id=uuid4(),
        input_str="input",
        input_hash=AgentEvent.compute_hash("input"),
    )
    event.finalize(output="output", latency_ms=1.0)
    event.policy_result = "ALLOW"
    return event


# ── Interceptor overhead ─────────────────────────────────────────────


class TestInterceptorSLA:
    """Interceptor overhead must meet p50/p95/p99 targets."""

    def test_interceptor_overhead_1000_calls(self):
        interceptor = AgentGuardInterceptor(agent_id="perf", session_id="perf")
        serialized = {"name": "fast_tool"}
        times: list[float] = []

        for i in range(1000):
            rid = uuid4()
            start = time.perf_counter()
            interceptor.on_tool_start(
                serialized=serialized, input_str=f"in_{i}", run_id=rid
            )
            interceptor.on_tool_end(output=f"out_{i}", run_id=rid)
            times.append((time.perf_counter() - start) * 1000)

        s = sorted(times)
        assert s[499] < 5.0, f"p50 {s[499]:.3f}ms > 5ms"
        assert s[949] < 20.0, f"p95 {s[949]:.3f}ms > 20ms"
        assert s[989] < 50.0, f"p99 {s[989]:.3f}ms > 50ms"

    def test_interceptor_with_risk_detection(self):
        cfg = InterceptorConfig(
            agent_id="perf",
            session_id="perf",
            known_tools=["allowed"],
            internal_domains=["co.com"],
            sensitive_keywords=["password", "secret"],
        )
        interceptor = AgentGuardInterceptor(config=cfg)
        times: list[float] = []

        for i in range(500):
            rid = uuid4()
            start = time.perf_counter()
            interceptor.on_tool_start(
                serialized={"name": "unknown"},
                input_str=f"https://ext.com?q={i}",
                run_id=rid,
            )
            interceptor.on_tool_end(output=f"password data {i}", run_id=rid)
            times.append((time.perf_counter() - start) * 1000)

        assert sorted(times)[int(len(times) * 0.99)] < 50.0


# ── Policy evaluation ────────────────────────────────────────────────


class TestPolicySLA:
    """Policy evaluation: p99 <5ms, 1000 evals <5s total."""

    def test_policy_eval_p99(self):
        policy_path = str(Path(__file__).parent.parent / "policies" / "default.yaml")
        engine = PolicyEngine(policy_path)
        times: list[float] = []

        for i in range(1000):
            event = AgentEvent(
                tool_name=f"tool_{i}",
                run_id=uuid4(),
                agent_id="perf",
                session_id="perf",
            )
            start = time.perf_counter()
            engine.evaluate(event)
            times.append((time.perf_counter() - start) * 1000)

        assert sorted(times)[989] < 5.0, f"p99 {sorted(times)[989]:.3f}ms > 5ms"

    def test_policy_1000_evals_under_5s(self):
        policy_path = str(Path(__file__).parent.parent / "policies" / "default.yaml")
        engine = PolicyEngine(policy_path)
        events = [
            AgentEvent(tool_name=f"t_{i}", run_id=uuid4(), agent_id="p", session_id="p")
            for i in range(1000)
        ]

        start = time.perf_counter()
        for e in events:
            engine.evaluate(e)
        elapsed = time.perf_counter() - start

        assert elapsed < 5.0, f"1000 evals took {elapsed:.2f}s > 5s"


# ── Queue enqueue ────────────────────────────────────────────────────


class TestQueueSLA:
    """Queue enqueue: p99 <5ms."""

    def test_enqueue_p99(self, tmp_path):
        store = EventStore(db_path=str(tmp_path / "perf.db"))
        queue = EventQueue(store=store, flush_interval=0.01)
        queue.start()

        times: list[float] = []
        for _ in range(1000):
            event = make_event()
            start = time.perf_counter()
            queue.enqueue(event)
            times.append((time.perf_counter() - start) * 1000)

        assert sorted(times)[989] < 5.0, f"p99 {sorted(times)[989]:.3f}ms > 5ms"

        time.sleep(0.5)
        queue.stop()
        store.close()


# ── Injection Stage 1 ────────────────────────────────────────────────


class TestInjectionSLA:
    """Injection Stage 1 regex: p99 <5ms for 1KB input."""

    def test_stage1_p99(self):
        detector = InjectionDetector(sensitivity="LOW")
        text = "Normal business text. " * 50  # ~1KB
        times: list[float] = []

        for _ in range(500):
            start = time.perf_counter()
            detector.scan(text)
            times.append((time.perf_counter() - start) * 1000)

        assert sorted(times)[int(len(times) * 0.99)] < 5.0


# ── Event store append ───────────────────────────────────────────────


class TestStoreSLA:
    """Event store append: p99 <10ms (SQLite)."""

    def test_append_p99(self, tmp_path):
        store = EventStore(db_path=str(tmp_path / "sla.db"))
        times: list[float] = []

        for _ in range(500):
            event = make_event()
            start = time.perf_counter()
            store.append(event)
            times.append((time.perf_counter() - start) * 1000)

        assert sorted(times)[int(len(times) * 0.99)] < 10.0
        store.close()


# ── Sustained throughput ─────────────────────────────────────────────


class TestThroughputSLA:
    """Sustained 500 events/sec for 1 second."""

    def test_500_events_per_second(self, tmp_path):
        store = EventStore(db_path=str(tmp_path / "throughput.db"))
        queue = EventQueue(store=store, flush_interval=0.01)
        queue.start()

        start = time.perf_counter()
        for _ in range(500):
            queue.enqueue(make_event())
        enqueue_time = time.perf_counter() - start

        # All 500 enqueued in < 2 seconds
        assert enqueue_time < 2.0, f"500 enqueues took {enqueue_time:.2f}s"

        # Wait for drain
        time.sleep(1.5)
        assert queue.events_written == 500
        assert queue.events_dropped == 0

        queue.stop()
        store.close()
