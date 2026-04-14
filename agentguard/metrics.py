"""Prometheus-compatible metrics for AgentGuard.

Tracks 5 core metrics with labels, exposed as text/plain at /metrics.
Thread-safe counters and gauges — no Prometheus client library needed.

Metrics:
    agentguard_events_total{agent_id, tool_name, policy_result}
    agentguard_policy_blocks_total{agent_id, tool_name}
    agentguard_dlp_detections_total{agent_id, entity_type}
    agentguard_injection_detections_total{agent_id, status}
    agentguard_latency_seconds{agent_id, tool_name, quantile}

Usage:
    from agentguard.metrics import MetricsCollector

    metrics = MetricsCollector()
    metrics.record_event(event)
    text = metrics.render()  # Prometheus text format
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict

from agentguard.models import AgentEvent


class MetricsCollector:
    """Thread-safe Prometheus metrics collector.

    Collects counters and latency histograms from AgentEvents.
    Renders as Prometheus text exposition format.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events_total: dict[tuple[str, str, str], int] = defaultdict(int)
        self._blocks_total: dict[tuple[str, str], int] = defaultdict(int)
        self._dlp_detections: dict[tuple[str, str], int] = defaultdict(int)
        self._injection_detections: dict[tuple[str, str], int] = defaultdict(int)
        self._latencies: list[float] = []
        self._latencies_by_tool: dict[str, list[float]] = defaultdict(list)
        self._start_time = time.time()

    def record_event(self, event: AgentEvent) -> None:
        """Record metrics from a completed event.

        Args:
            event: A finalized AgentEvent.
        """
        with self._lock:
            # Counter: total events by agent, tool, policy
            key = (event.agent_id, event.tool_name, event.policy_result)
            self._events_total[key] += 1

            # Counter: blocks
            if event.policy_result == "BLOCK":
                self._blocks_total[(event.agent_id, event.tool_name)] += 1

            # Counter: DLP detections
            if "pii_detected" in event.risk_flags:
                self._dlp_detections[(event.agent_id, "pii_detected")] += 1

            # Counter: injection detections
            for flag in event.risk_flags:
                if flag in ("injection_detected",):
                    self._injection_detections[(event.agent_id, flag)] += 1

            # Latency histogram
            if event.latency_ms is not None:
                self._latencies.append(event.latency_ms)
                self._latencies_by_tool[event.tool_name].append(event.latency_ms)

    def render(self, version: str = "0.1.0") -> str:
        """Render all metrics as Prometheus text exposition format.

        Args:
            version: AgentGuard version string.

        Returns:
            Prometheus-compatible text/plain string.
        """
        with self._lock:
            lines: list[str] = []

            # ── agentguard_events_total ──────────────────────────
            lines.append(
                "# HELP agentguard_events_total Total tool-call events processed"
            )
            lines.append("# TYPE agentguard_events_total counter")
            for (agent, tool, policy), count in sorted(self._events_total.items()):
                lines.append(
                    f'agentguard_events_total{{agent_id="{agent}",tool_name="{tool}",'
                    f'policy_result="{policy}"}} {count}'
                )

            # ── agentguard_policy_blocks_total ────────────────────
            lines.append("")
            lines.append("# HELP agentguard_policy_blocks_total Total BLOCK decisions")
            lines.append("# TYPE agentguard_policy_blocks_total counter")
            for (agent, tool), count in sorted(self._blocks_total.items()):
                lines.append(
                    f'agentguard_policy_blocks_total{{agent_id="{agent}",tool_name="{tool}"}} {count}'
                )

            # ── agentguard_dlp_detections_total ──────────────────
            lines.append("")
            lines.append(
                "# HELP agentguard_dlp_detections_total Total DLP PII detections"
            )
            lines.append("# TYPE agentguard_dlp_detections_total counter")
            for (agent, entity_type), count in sorted(self._dlp_detections.items()):
                lines.append(
                    f'agentguard_dlp_detections_total{{agent_id="{agent}",entity_type="{entity_type}"}} {count}'
                )

            # ── agentguard_injection_detections_total ─────────────
            lines.append("")
            lines.append(
                "# HELP agentguard_injection_detections_total Total injection detections"
            )
            lines.append("# TYPE agentguard_injection_detections_total counter")
            for (agent, status), count in sorted(self._injection_detections.items()):
                lines.append(
                    f'agentguard_injection_detections_total{{agent_id="{agent}",status="{status}"}} {count}'
                )

            # ── agentguard_latency_seconds ────────────────────────
            lines.append("")
            lines.append(
                "# HELP agentguard_latency_seconds Tool call latency in seconds"
            )
            lines.append("# TYPE agentguard_latency_seconds summary")
            if self._latencies:
                sorted_lat = sorted(self._latencies)
                n = len(sorted_lat)
                p50 = sorted_lat[int(n * 0.5)] / 1000
                p95 = sorted_lat[int(n * 0.95)] / 1000
                p99 = sorted_lat[min(int(n * 0.99), n - 1)] / 1000
                lines.append(f'agentguard_latency_seconds{{quantile="0.5"}} {p50:.6f}')
                lines.append(f'agentguard_latency_seconds{{quantile="0.95"}} {p95:.6f}')
                lines.append(f'agentguard_latency_seconds{{quantile="0.99"}} {p99:.6f}')
                lines.append(f"agentguard_latency_seconds_count {n}")
                lines.append(
                    f"agentguard_latency_seconds_sum {sum(self._latencies) / 1000:.6f}"
                )

            # ── agentguard_version ────────────────────────────────
            lines.append("")
            lines.append("# HELP agentguard_version AgentGuard version info")
            lines.append("# TYPE agentguard_version gauge")
            lines.append(f'agentguard_version{{version="{version}"}} 1')

            # ── agentguard_uptime_seconds ─────────────────────────
            lines.append("")
            lines.append(
                "# HELP agentguard_uptime_seconds Time since metrics collector started"
            )
            lines.append("# TYPE agentguard_uptime_seconds gauge")
            lines.append(
                f"agentguard_uptime_seconds {time.time() - self._start_time:.1f}"
            )

            lines.append("")
            return "\n".join(lines)

    def reset(self) -> None:
        """Reset all metrics (useful for testing)."""
        with self._lock:
            self._events_total.clear()
            self._blocks_total.clear()
            self._dlp_detections.clear()
            self._injection_detections.clear()
            self._latencies.clear()
            self._latencies_by_tool.clear()
            self._start_time = time.time()
