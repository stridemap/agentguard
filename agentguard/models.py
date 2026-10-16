"""Pydantic v2 data models for AgentGuard.

Defines the core event schema used across all AgentGuard modules:
interceptor, event store, policy engine, and audit chain.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class PolicyResult(StrEnum):
    """Possible outcomes of a policy evaluation."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ALERT = "ALERT"
    BYPASS = "BYPASS"
    PENDING = "PENDING"


class RiskFlag(StrEnum):
    """Auto-detected risk indicators for tool call events."""

    EXTERNAL_DOMAIN = "external_domain"
    LARGE_PAYLOAD = "large_payload"
    SENSITIVE_KEYWORD = "sensitive_keyword"
    HIGH_FREQUENCY = "high_frequency"
    UNKNOWN_TOOL = "unknown_tool"
    PII_DETECTED = "pii_detected"


class AlertSeverity(StrEnum):
    """Severity levels for policy alerts."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AgentEvent(BaseModel):
    """A single tool-call event captured by the AgentGuard interceptor.

    Each event represents one invocation of a tool by an AI agent,
    recording metadata, timing, risk flags, and policy decisions.

    The event lifecycle:
        1. on_tool_start: event created with input data, status=STARTED
        2. Policy/DLP/injection checks run (future sprints)
        3. on_tool_end: event completed with output data, latency calculated
    """

    event_id: UUID = Field(
        default_factory=uuid4, description="Unique event identifier (UUID4)"
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Event creation time in UTC (ISO 8601)",
    )
    agent_id: str = Field(
        default="unknown", description="Identifier of the agent that made the tool call"
    )
    session_id: str = Field(
        default="unknown", description="Session identifier for grouping related events"
    )
    tool_name: str = Field(description="Name of the tool being called")
    run_id: UUID = Field(description="LangChain/LangGraph run ID for this tool call")
    parent_run_id: UUID | None = Field(
        default=None, description="Parent run ID (the agent's run)"
    )

    input_str: str = Field(
        default="", description="Raw input string passed to the tool"
    )
    input_hash: str = Field(default="", description="SHA-256 hash of the input string")
    output_str: str = Field(
        default="", description="Raw output string returned by the tool"
    )
    output_hash: str = Field(
        default="", description="SHA-256 hash of the output string"
    )

    latency_ms: float | None = Field(
        default=None, description="Tool execution latency in milliseconds"
    )
    risk_flags: list[RiskFlag] = Field(
        default_factory=list, description="Auto-detected risk indicators"
    )
    dlp_entities: list[str] = Field(
        default_factory=list,
        description="PII entity types the scanner found, e.g. US_SSN. Policy rules match "
        "on these by name.",
    )
    """Carried separately from `risk_flags` because that is a closed enum of generic
    indicators — it can record *that* PII was present, never *which kind*. A rule written
    as `data_pattern: US_SSN` needs the latter, and redaction removes the value from the
    payload before policy runs, so the text is no longer a reliable place to look."""
    policy_result: PolicyResult = Field(
        default=PolicyResult.PENDING, description="Policy evaluation outcome"
    )

    completed: bool = Field(
        default=False, description="Whether on_tool_end has been called for this event"
    )

    model_config = {"frozen": False, "use_enum_values": True}

    @staticmethod
    def compute_hash(text: str) -> str:
        """Compute SHA-256 hash of a string."""
        return hashlib.sha256(text.encode()).hexdigest()

    def finalize(self, output: str, latency_ms: float) -> None:
        """Complete the event after tool execution.

        Args:
            output: The raw output string from the tool.
            latency_ms: Execution time in milliseconds.
        """
        self.output_str = output
        self.output_hash = self.compute_hash(output)
        self.latency_ms = latency_ms
        self.completed = True


class InterceptorConfig(BaseModel):
    """Configuration for the AgentGuard interceptor.

    Controls agent/session identification, risk detection thresholds,
    and payload size limits.
    """

    agent_id: str = Field(
        default="default-agent", description="Identifier for the agent being monitored"
    )
    session_id: str = Field(
        default="default-session", description="Session identifier for event grouping"
    )
    large_payload_threshold_bytes: int = Field(
        default=10_240,
        description="Output size in bytes above which large_payload risk flag is triggered",
    )
    high_frequency_threshold: int = Field(
        default=10,
        description="Number of tool calls per minute above which high_frequency risk flag is triggered",
    )
    high_frequency_window_seconds: int = Field(
        default=60,
        description="Time window in seconds for high-frequency detection",
    )
    sensitive_keywords: list[str] = Field(
        default_factory=lambda: [
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
            "credential",
        ],
        description="Keywords that trigger sensitive_keyword risk flag when found in input or output",
    )
    internal_domains: list[str] = Field(
        default_factory=list,
        description="Domain allowlist for internal/trusted endpoints. "
        "URLs matching these domains are NOT flagged as external_domain. "
        "Empty list = all external URLs are flagged.",
    )
    known_tools: list[str] = Field(
        default_factory=list,
        description="Allowlist of known-good tool names. "
        "Tools not in this list are flagged as unknown_tool. "
        "Empty list = unknown_tool detection disabled.",
    )
