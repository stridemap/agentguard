"""Shared test fixtures for AgentGuard test suite."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

# ── Database Fixtures ──────────────────────────────────────────────────


@pytest.fixture()
def tmp_db(tmp_path):
    """Return a temporary SQLite database path for test isolation."""
    return str(tmp_path / "test_agentguard.db")


# ── LLM Fixtures ──────────────────────────────────────────────────────


@pytest.fixture()
def mock_llm():
    """Mock LLM client that returns deterministic classification responses.

    Usage:
        def test_injection_classifier(mock_llm):
            mock_llm.classify.return_value = "CLEAN"
            result = detector.scan("hello", llm_client=mock_llm)
            assert result.classification == "CLEAN"
    """
    client = MagicMock()
    client.classify.return_value = "CLEAN"
    client.provider = "mock"
    client.model = "mock-model"
    return client


# ── Event Fixtures ────────────────────────────────────────────────────


@pytest.fixture()
def sample_event():
    """Return a pre-built event dict for quick test setup.

    Mirrors the AgentEvent schema defined in agentguard/models.py.
    """
    return {
        "event_id": "550e8400-e29b-41d4-a716-446655440000",
        "timestamp": "2026-04-09T12:00:00Z",
        "agent_id": "test-agent-001",
        "session_id": "sess-abc-123",
        "tool_name": "send_email",
        "input_hash": "a" * 64,
        "output_hash": "b" * 64,
        "latency_ms": 12.5,
        "risk_flags": [],
        "policy_result": "ALLOW",
    }


@pytest.fixture()
def sample_event_blocked(sample_event):
    """Return a sample event with BLOCK policy result and risk flags."""
    return {
        **sample_event,
        "event_id": "550e8400-e29b-41d4-a716-446655440001",
        "policy_result": "BLOCK",
        "risk_flags": ["pii_detected", "external_domain"],
    }


# ── Policy Fixtures ──────────────────────────────────────────────────


@pytest.fixture()
def sample_policy_yaml(tmp_path):
    """Create a temporary YAML policy file with test rules.

    Returns the path to the temporary file.
    """
    policy_content = """\
rules:
  - id: "block_external_email_with_pii"
    name: "Block External Email with PII"
    description: "Block sending PII to external email domains"
    priority: 10
    conditions:
      tool_name: "send_email"
      destination_domain: "!internal.com"
      data_pattern: "US_SSN"
      direction: "output"
      agent_id: null
    action: "BLOCK"
    alert_severity: "CRITICAL"

  - id: "allow_internal_tools"
    name: "Allow Internal Tools"
    description: "Allow all calls to internal tool endpoints"
    priority: 100
    conditions:
      tool_name: null
      destination_domain: "internal.com"
      data_pattern: null
      direction: "both"
      agent_id: null
    action: "ALLOW"
    alert_severity: "LOW"

  - id: "alert_large_payload"
    name: "Alert Large Payload"
    description: "Alert when tool output exceeds 10KB"
    priority: 50
    conditions:
      tool_name: null
      destination_domain: null
      data_pattern: null
      direction: "output"
      agent_id: null
    action: "ALERT"
    alert_severity: "MEDIUM"
"""
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(policy_content)
    return str(policy_file)


# ── DLP Fixtures ─────────────────────────────────────────────────────


@pytest.fixture()
def mock_presidio():
    """Mock Presidio analyzer for DLP tests without the full dependency.

    Returns a mock that simulates Presidio's analyze() method.
    """
    analyzer = MagicMock()

    # Default: return no entities (clean text)
    analyzer.analyze.return_value = []

    return analyzer


@pytest.fixture()
def pii_samples():
    """Return a dict of PII samples for DLP testing."""
    return {
        "ssn": "My SSN is 123-45-6789",
        "credit_card": "Card number: 4111-1111-1111-1111",
        "email": "Contact me at john.doe@example.com",
        "phone": "Call me at (555) 123-4567",
        "clean": "The quarterly report shows a 15% increase in revenue.",
    }


# ── Performance Helpers ──────────────────────────────────────────────


@pytest.fixture()
def assert_latency():
    """Return a helper function for asserting latency percentiles.

    Usage:
        def test_fast(assert_latency):
            times = [measure() for _ in range(1000)]
            assert_latency(times, p50=5, p95=20, p99=50)
    """

    def _assert(times_ms: list[float], p50: float, p95: float, p99: float):
        sorted_times = sorted(times_ms)
        n = len(sorted_times)
        actual_p50 = sorted_times[int(n * 0.50)]
        actual_p95 = sorted_times[int(n * 0.95)]
        actual_p99 = sorted_times[int(n * 0.99)]
        assert actual_p50 < p50, f"p50 {actual_p50:.2f}ms exceeds {p50}ms"
        assert actual_p95 < p95, f"p95 {actual_p95:.2f}ms exceeds {p95}ms"
        assert actual_p99 < p99, f"p99 {actual_p99:.2f}ms exceeds {p99}ms"

    return _assert
