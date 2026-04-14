"""SIEM webhook client for forwarding high-severity events.

Sends CEF-formatted (Common Event Format) events to configurable
SIEM endpoints — Splunk HEC, Datadog, Microsoft Sentinel, or any
webhook that accepts HTTP POST.

CEF format:
  CEF:0|Stridemap|AgentGuard|1.0|{rule_id}|{rule_name}|{severity}|...

Also supports a JSON alert webhook for BLOCK/CRITICAL events.

Usage:
    from agentguard.siem import SIEMClient, AlertWebhook

    siem = SIEMClient(webhook_url="https://splunk.example.com/services/collector")
    siem.send(event)

    alerter = AlertWebhook(url="https://hooks.slack.com/...", on_actions=["BLOCK"])
    alerter.send(event)
"""

from __future__ import annotations

import json
import os

import httpx

from agentguard.logging import logger
from agentguard.models import AgentEvent

# ── CEF Formatter ────────────────────────────────────────────────────


_CEF_SEVERITY_MAP = {
    "LOW": 3,
    "MEDIUM": 5,
    "HIGH": 8,
    "CRITICAL": 10,
    "ALLOW": 1,
    "ALERT": 5,
    "BLOCK": 9,
    "BYPASS": 1,
}


def format_cef(event: AgentEvent, rule_id: str = "", rule_name: str = "") -> str:
    """Format an AgentEvent as a CEF string.

    CEF:0|Stridemap|AgentGuard|1.0|rule_id|rule_name|severity|extensions

    Args:
        event: The AgentEvent to format.
        rule_id: Policy rule ID that matched (if any).
        rule_name: Policy rule name that matched (if any).

    Returns:
        CEF-formatted string.
    """
    severity = _CEF_SEVERITY_MAP.get(event.policy_result, 3)
    if not rule_id:
        rule_id = event.policy_result
    if not rule_name:
        rule_name = f"{event.tool_name} — {event.policy_result}"

    extensions = (
        f"agentId={event.agent_id} "
        f"sessionId={event.session_id} "
        f"toolName={event.tool_name} "
        f"policyResult={event.policy_result} "
        f"riskFlags={','.join(event.risk_flags) if event.risk_flags else 'none'} "
        f"latencyMs={event.latency_ms or 0:.1f} "
        f"eventId={event.event_id} "
        f"rt={int(event.timestamp.timestamp() * 1000)}"
    )

    return (
        f"CEF:0|Stridemap|AgentGuard|1.0|{rule_id}|{rule_name}|{severity}|{extensions}"
    )


# ── SIEM Client ──────────────────────────────────────────────────────


class SIEMClient:
    """HTTP webhook client for forwarding events to SIEM systems.

    Supports Splunk HEC, Datadog, Microsoft Sentinel, or any endpoint
    that accepts CEF-formatted POST requests.

    Attributes:
        webhook_url: The SIEM endpoint URL.
        format: 'cef' or 'json' output format.
        auth_token: Optional Bearer / HEC token for authentication.
    """

    def __init__(
        self,
        webhook_url: str | None = None,
        format: str = "cef",
        auth_token: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.webhook_url = webhook_url or os.environ.get(
            "AGENTGUARD_SIEM_WEBHOOK_URL", ""
        )
        self.format = format
        self.auth_token = auth_token or os.environ.get("AGENTGUARD_SIEM_TOKEN", "")
        self.timeout = timeout
        self._events_sent = 0
        self._events_failed = 0

    @property
    def is_configured(self) -> bool:
        """Return True if a webhook URL is set."""
        return bool(self.webhook_url)

    @property
    def events_sent(self) -> int:
        return self._events_sent

    @property
    def events_failed(self) -> int:
        return self._events_failed

    def send(self, event: AgentEvent, rule_id: str = "", rule_name: str = "") -> bool:
        """Send an event to the configured SIEM webhook.

        Args:
            event: The AgentEvent to forward.
            rule_id: Optional policy rule ID.
            rule_name: Optional policy rule name.

        Returns:
            True if sent successfully, False if failed or not configured.
        """
        if not self.is_configured:
            return False

        try:
            headers: dict[str, str] = {"Content-Type": "text/plain"}
            if self.auth_token:
                headers["Authorization"] = f"Splunk {self.auth_token}"

            if self.format == "json":
                body = json.dumps(
                    {
                        "event": {
                            "event_id": str(event.event_id),
                            "timestamp": event.timestamp.isoformat(),
                            "agent_id": event.agent_id,
                            "session_id": event.session_id,
                            "tool_name": event.tool_name,
                            "policy_result": event.policy_result,
                            "risk_flags": event.risk_flags,
                            "latency_ms": event.latency_ms,
                        },
                        "source": "agentguard",
                        "sourcetype": "agentguard:event",
                    }
                )
                headers["Content-Type"] = "application/json"
            else:
                body = format_cef(event, rule_id, rule_name)

            response = httpx.post(
                self.webhook_url,
                content=body,
                headers=headers,
                timeout=self.timeout,
            )
            response.raise_for_status()
            self._events_sent += 1

            logger.bind(module="agentguard.siem").debug(
                "SIEM event sent: {event_id} → {url} ({status})",
                event_id=str(event.event_id),
                url=self.webhook_url[:50],
                status=response.status_code,
            )
            return True

        except Exception as e:
            self._events_failed += 1
            logger.opt(exception=True).warning(
                "SIEM send failed for {event_id}: {error}",
                event_id=str(event.event_id),
                error=str(e)[:200],
            )
            return False


# ── Alert Webhook ────────────────────────────────────────────────────


class AlertWebhook:
    """Configurable POST webhook triggered on BLOCK/CRITICAL events.

    Sends a JSON payload when an event matches the configured actions
    (default: BLOCK). Used for Slack, PagerDuty, email, or custom alerts.

    Attributes:
        url: The alert webhook URL.
        on_actions: Policy results that trigger an alert.
    """

    def __init__(
        self,
        url: str | None = None,
        on_actions: list[str] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.url = url or os.environ.get("AGENTGUARD_ALERT_WEBHOOK_URL", "")
        self.on_actions = on_actions or ["BLOCK"]
        self.timeout = timeout
        self._alerts_sent = 0
        self._alerts_failed = 0

    @property
    def is_configured(self) -> bool:
        return bool(self.url)

    @property
    def alerts_sent(self) -> int:
        return self._alerts_sent

    @property
    def alerts_failed(self) -> int:
        return self._alerts_failed

    def should_alert(self, event: AgentEvent) -> bool:
        """Check if this event should trigger an alert."""
        return event.policy_result in self.on_actions

    def send(self, event: AgentEvent) -> bool:
        """Send an alert if the event matches configured actions.

        Args:
            event: The AgentEvent to check and potentially alert on.

        Returns:
            True if alert sent, False if not triggered or failed.
        """
        if not self.is_configured or not self.should_alert(event):
            return False

        try:
            payload = {
                "text": (
                    f"🛡️ AgentGuard Alert: {event.policy_result}\n"
                    f"Tool: {event.tool_name}\n"
                    f"Agent: {event.agent_id}\n"
                    f"Risk Flags: {', '.join(event.risk_flags) or 'none'}\n"
                    f"Event ID: {event.event_id}\n"
                    f"Time: {event.timestamp.isoformat()}"
                ),
                "event": {
                    "event_id": str(event.event_id),
                    "timestamp": event.timestamp.isoformat(),
                    "agent_id": event.agent_id,
                    "tool_name": event.tool_name,
                    "policy_result": event.policy_result,
                    "risk_flags": event.risk_flags,
                    "latency_ms": event.latency_ms,
                },
            }

            response = httpx.post(
                self.url,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            self._alerts_sent += 1

            logger.bind(module="agentguard.siem").info(
                "Alert sent for {event_id}: {action} on {tool}",
                event_id=str(event.event_id),
                action=event.policy_result,
                tool=event.tool_name,
            )
            return True

        except Exception as e:
            self._alerts_failed += 1
            logger.opt(exception=True).warning(
                "Alert webhook failed: {error}", error=str(e)[:200]
            )
            return False
