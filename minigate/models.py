"""Framework-neutral event model for MiniGate.

`McpEvent` describes one governed message on the MCP wire. Unlike AgentGuard's
`AgentEvent` it carries no assumptions about a callback graph (no `run_id` /
`parent_run_id`), which is what allows MiniGate to govern any MCP client
regardless of the framework the agent was built with.

`to_agent_event()` maps an McpEvent onto AgentGuard's `AgentEvent` so the existing
policy engine, audit chain, and dashboard work unchanged. That bridge is a
compatibility layer, not the direction of travel — MiniGate's native type is
`McpEvent`.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from agentguard.models import AgentEvent, PolicyResult, RiskFlag


class Direction(StrEnum):
    """Which way the governed payload is travelling."""

    REQUEST = "request"
    """Client to server — arguments leaving the model, heading for an external system."""

    RESPONSE = "response"
    """Server to client — content entering model context, the indirect-injection surface."""


class McpEvent(BaseModel):
    """A single governed MCP message.

    One event is emitted per policy decision: per `tools/call` in each direction,
    and one per `tools/list` describing what was filtered.
    """

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    client_id: str = Field(
        default="unknown",
        description="Which MCP client is connected (claude-desktop, cursor, ...)",
    )
    session_id: str = Field(default="unknown", description="MiniGate session identifier")
    server: str = Field(description="Configured name of the upstream MCP server")

    method: str = Field(description="JSON-RPC method, e.g. tools/call")
    tool: str | None = Field(default=None, description="Unqualified tool name, if any")
    resource_uri: str | None = Field(
        default=None, description="Resource URI, for resources/* methods"
    )
    prompt_name: str | None = Field(
        default=None, description="Prompt name, for prompts/* methods"
    )
    direction: Direction = Field(description="request | response")
    rpc_id: str | None = Field(default=None, description="JSON-RPC id this event relates to")

    payload: str = Field(default="", description="Governed payload, redacted if DLP matched")
    payload_hash: str = Field(default="", description="SHA-256 of the payload as stored")

    policy_result: str = Field(default="PENDING", description="ALLOW | BLOCK | ALERT | BYPASS")
    matched_rule: str | None = Field(default=None)
    reason: str = Field(default="")

    dlp_entities: list[str] = Field(
        default_factory=list, description="PII entity types detected in the payload"
    )
    injection_status: str = Field(default="CLEAN", description="CLEAN | SUSPICIOUS | INJECTED")
    registry_verdict: str | None = Field(
        default=None, description="APPROVED | CHANGED | UNKNOWN, if the registry was consulted"
    )
    lineage_sources: list[str] = Field(
        default_factory=list,
        description="Sources whose data reached this call, when a trust boundary was crossed",
    )
    trust_level: str | None = Field(
        default=None, description="Trust level of this server or tool, if lineage is in use"
    )
    filtered_tools: list[str] = Field(
        default_factory=list, description="Tools withheld from the model on tools/list"
    )
    latency_ms: float | None = Field(default=None, description="Governance overhead")

    model_config = {"use_enum_values": True}

    @staticmethod
    def compute_hash(text: str) -> str:
        """SHA-256 of a string, matching AgentGuard's hashing convention."""
        return hashlib.sha256(text.encode()).hexdigest()

    @property
    def qualified_tool(self) -> str:
        """The policy-facing name for this event.

        Four shapes, because a policy has to be able to address four different things:

            <server>.<tool>            a tool call
            <server>.resource:<uri>    a resource, addressed by URI rather than name
            <server>.prompt:<name>     a prompt template
            <server>.<method>          anything else, e.g. `notion.tools/list`

        Qualifying by server is what lets one policy file govern many MCP servers without
        name collisions, and the `resource:` and `prompt:` prefixes keep the three kinds
        of target from colliding with each other in the same namespace.
        """
        if self.resource_uri:
            return f"{self.server}.resource:{self.resource_uri}"
        if self.prompt_name:
            return f"{self.server}.prompt:{self.prompt_name}"
        if self.tool:
            return f"{self.server}.{self.tool}"
        return f"{self.server}.{self.method}"

    def to_agent_event(self) -> AgentEvent:
        """Map onto AgentGuard's AgentEvent for policy evaluation and persistence.

        The payload lands in `input_str` for requests and `output_str` for responses,
        which is what AgentGuard's `direction` conditions ('input' / 'output') match on.

        The decision fields are carried across too: an audit row that records a tool
        call without recording whether it was allowed or blocked is not an audit trail.
        Called both before evaluation (where they are still PENDING) and at emit time.
        """
        is_request = self.direction == Direction.REQUEST
        event = AgentEvent(
            event_id=self.event_id,
            timestamp=self.timestamp,
            agent_id=self.client_id,
            session_id=self.session_id,
            tool_name=self.qualified_tool,
            run_id=uuid4(),
            input_str=self.payload if is_request else "",
            output_str="" if is_request else self.payload,
            latency_ms=self.latency_ms,
            policy_result=self._policy_result(),
            risk_flags=[RiskFlag.PII_DETECTED] if self.dlp_entities else [],
            dlp_entities=list(self.dlp_entities),
            completed=not is_request,
        )
        event.input_hash = self.compute_hash(event.input_str)
        event.output_hash = self.compute_hash(event.output_str)
        return event

    def _policy_result(self) -> PolicyResult:
        """Coerce the decision to AgentGuard's enum, defaulting to PENDING."""
        try:
            return PolicyResult(self.policy_result)
        except ValueError:
            return PolicyResult.PENDING
