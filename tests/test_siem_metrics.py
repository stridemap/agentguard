"""Tests for SIEM integration, Prometheus metrics, and alert webhook.

Covers:
- CEF format output
- SIEM client send (mocked HTTP)
- Alert webhook trigger conditions
- MetricsCollector: record, render, counters, latency quantiles
- VPC egress: no outbound connections when SIEM not configured
- Integration: interceptor records metrics on every tool call
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch
from uuid import uuid4

from agentguard.interceptor import AgentGuardInterceptor
from agentguard.metrics import MetricsCollector
from agentguard.models import AgentEvent
from agentguard.siem import AlertWebhook, SIEMClient, format_cef

# ── Helpers ──────────────────────────────────────────────────────────


def make_event(
    tool_name: str = "send_email",
    policy_result: str = "ALLOW",
    risk_flags: list[str] | None = None,
    latency_ms: float = 5.0,
) -> AgentEvent:
    event = AgentEvent(
        agent_id="test-agent",
        session_id="test-session",
        tool_name=tool_name,
        run_id=uuid4(),
        input_str="input",
        input_hash=AgentEvent.compute_hash("input"),
    )
    event.finalize(output="output", latency_ms=latency_ms)
    event.policy_result = policy_result
    if risk_flags:
        event.risk_flags = risk_flags
    return event


# ── CEF format tests ─────────────────────────────────────────────────


class TestCEFFormat:
    def test_basic_cef_output(self):
        event = make_event()
        cef = format_cef(event)
        assert cef.startswith("CEF:0|Stridemap|AgentGuard|1.0|")
        assert "agentId=test-agent" in cef
        assert "toolName=send_email" in cef
        assert "policyResult=ALLOW" in cef

    def test_cef_with_rule_id(self):
        event = make_event(policy_result="BLOCK")
        cef = format_cef(event, rule_id="block_ssn", rule_name="Block SSN")
        assert "block_ssn|Block SSN|" in cef

    def test_cef_severity_mapping(self):
        block_event = make_event(policy_result="BLOCK")
        cef = format_cef(block_event)
        assert "|9|" in cef  # BLOCK = severity 9

        allow_event = make_event(policy_result="ALLOW")
        cef = format_cef(allow_event)
        assert "|1|" in cef  # ALLOW = severity 1

    def test_cef_risk_flags(self):
        event = make_event(risk_flags=["sensitive_keyword", "external_domain"])
        cef = format_cef(event)
        assert "riskFlags=sensitive_keyword,external_domain" in cef

    def test_cef_no_risk_flags(self):
        event = make_event()
        cef = format_cef(event)
        assert "riskFlags=none" in cef


# ── SIEM Client tests ────────────────────────────────────────────────


class TestSIEMClient:
    def test_not_configured_returns_false(self):
        client = SIEMClient(webhook_url="")
        assert not client.is_configured
        assert client.send(make_event()) is False

    def test_configured_sends_cef(self):
        client = SIEMClient(webhook_url="https://siem.example.com/hec")
        event = make_event()

        with patch("agentguard.siem.httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            result = client.send(event)

        assert result is True
        assert client.events_sent == 1
        call_args = mock_post.call_args
        assert "CEF:0" in call_args.kwargs.get(
            "content", call_args[1].get("content", "")
        )

    def test_json_format(self):
        client = SIEMClient(webhook_url="https://siem.example.com", format="json")
        event = make_event()

        with patch("agentguard.siem.httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            client.send(event)

        call_args = mock_post.call_args
        assert "application/json" in str(call_args)

    def test_send_failure_increments_failed_counter(self):
        client = SIEMClient(webhook_url="https://siem.example.com")

        with patch("agentguard.siem.httpx.post", side_effect=Exception("timeout")):
            result = client.send(make_event())

        assert result is False
        assert client.events_failed == 1

    def test_auth_token_sent_as_header(self):
        client = SIEMClient(
            webhook_url="https://splunk.example.com",
            auth_token="my-hec-token",
        )

        with patch("agentguard.siem.httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            client.send(make_event())

        headers = mock_post.call_args.kwargs.get("headers", {})
        assert headers.get("Authorization") == "Splunk my-hec-token"


# ── Alert Webhook tests ──────────────────────────────────────────────


class TestAlertWebhook:
    def test_not_configured_returns_false(self):
        alert = AlertWebhook(url="")
        assert not alert.is_configured
        assert alert.send(make_event()) is False

    def test_triggers_on_block(self):
        alert = AlertWebhook(url="https://alerts.example.com", on_actions=["BLOCK"])
        event = make_event(policy_result="BLOCK")
        assert alert.should_alert(event) is True

    def test_does_not_trigger_on_allow(self):
        alert = AlertWebhook(url="https://alerts.example.com", on_actions=["BLOCK"])
        event = make_event(policy_result="ALLOW")
        assert alert.should_alert(event) is False

    def test_sends_json_payload(self):
        alert = AlertWebhook(url="https://alerts.example.com", on_actions=["BLOCK"])
        event = make_event(policy_result="BLOCK")

        with patch("agentguard.siem.httpx.post") as mock_post:
            mock_post.return_value = MagicMock(status_code=200)
            mock_post.return_value.raise_for_status = MagicMock()
            result = alert.send(event)

        assert result is True
        assert alert.alerts_sent == 1

    def test_failure_increments_counter(self):
        alert = AlertWebhook(url="https://alerts.example.com", on_actions=["BLOCK"])

        with patch("agentguard.siem.httpx.post", side_effect=Exception("fail")):
            alert.send(make_event(policy_result="BLOCK"))

        assert alert.alerts_failed == 1

    def test_custom_actions(self):
        alert = AlertWebhook(
            url="https://alerts.example.com",
            on_actions=["BLOCK", "ALERT"],
        )
        assert alert.should_alert(make_event(policy_result="ALERT")) is True
        assert alert.should_alert(make_event(policy_result="ALLOW")) is False


# ── Metrics Collector tests ──────────────────────────────────────────


class TestMetricsCollector:
    def test_record_event(self):
        m = MetricsCollector()
        m.record_event(make_event())
        text = m.render()
        assert "agentguard_events_total" in text
        assert 'tool_name="send_email"' in text

    def test_block_counted(self):
        m = MetricsCollector()
        m.record_event(make_event(policy_result="BLOCK"))
        text = m.render()
        assert "agentguard_policy_blocks_total" in text
        assert "1" in text

    def test_dlp_detection_counted(self):
        m = MetricsCollector()
        m.record_event(make_event(risk_flags=["pii_detected"]))
        text = m.render()
        assert "agentguard_dlp_detections_total" in text

    def test_latency_quantiles(self):
        m = MetricsCollector()
        for i in range(100):
            m.record_event(make_event(latency_ms=float(i)))
        text = m.render()
        assert 'quantile="0.5"' in text
        assert 'quantile="0.95"' in text
        assert 'quantile="0.99"' in text
        assert "agentguard_latency_seconds_count 100" in text

    def test_version_in_output(self):
        m = MetricsCollector()
        text = m.render(version="1.2.3")
        assert 'version="1.2.3"' in text

    def test_uptime_in_output(self):
        m = MetricsCollector()
        text = m.render()
        assert "agentguard_uptime_seconds" in text

    def test_reset(self):
        m = MetricsCollector()
        m.record_event(make_event())
        m.reset()
        text = m.render()
        assert "agentguard_latency_seconds_count" not in text

    def test_prometheus_text_format(self):
        m = MetricsCollector()
        m.record_event(make_event())
        text = m.render()
        # Verify Prometheus format conventions
        assert text.count("# HELP") >= 5
        assert text.count("# TYPE") >= 5


# ── VPC egress test ──────────────────────────────────────────────────


class TestVPCEgress:
    def test_no_outbound_when_siem_not_configured(self):
        """Confirm zero outbound HTTP calls when SIEM is not configured."""
        client = SIEMClient(webhook_url="")
        alert = AlertWebhook(url="")

        with patch("agentguard.siem.httpx.post") as mock_post:
            client.send(make_event())
            alert.send(make_event(policy_result="BLOCK"))

        mock_post.assert_not_called()


# ── Interceptor integration ──────────────────────────────────────────


class TestInterceptorMetrics:
    def test_metrics_recorded_on_tool_call(self):
        interceptor = AgentGuardInterceptor(agent_id="metrics-test")
        rid = uuid4()
        interceptor.on_tool_start(
            serialized={"name": "test_tool"}, input_str="hello", run_id=rid
        )
        interceptor.on_tool_end(output="world", run_id=rid)

        text = interceptor.metrics.render()
        assert "agentguard_events_total" in text
        assert 'tool_name="test_tool"' in text

    def test_metrics_tracks_multiple_events(self):
        interceptor = AgentGuardInterceptor(agent_id="multi")
        for i in range(10):
            rid = uuid4()
            interceptor.on_tool_start(
                serialized={"name": "tool"}, input_str=f"in_{i}", run_id=rid
            )
            interceptor.on_tool_end(output=f"out_{i}", run_id=rid)

        text = interceptor.metrics.render()
        assert "agentguard_latency_seconds_count 10" in text
