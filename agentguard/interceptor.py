"""LangGraph/LangChain BaseCallbackHandler interceptor for tool-call governance.

AgentGuardInterceptor sits between AI agents and their tools, capturing
every tool call as a structured AgentEvent. It is designed with a
fail-open guarantee: any exception inside the interceptor is caught
and logged — the agent's tool call is NEVER blocked due to interceptor errors.

All logging uses Loguru structured JSON — no print() statements.

Usage:
    from agentguard import AgentGuardInterceptor

    interceptor = AgentGuardInterceptor(agent_id="my-agent", session_id="sess-001")
    config = {"callbacks": [interceptor]}
    agent.invoke(input, config=config)
"""

from __future__ import annotations

import re
import time
from collections import deque
from typing import Any
from uuid import UUID

from langchain_core.callbacks import BaseCallbackHandler

from agentguard.dlp_scanner import DLPScanner
from agentguard.event_store import EventQueue, EventStore
from agentguard.injection_detector import InjectionDetector
from agentguard.logging import logger
from agentguard.models import AgentEvent, InterceptorConfig, RiskFlag
from agentguard.policy_engine import PolicyEngine


class AgentGuardInterceptor(BaseCallbackHandler):
    """BaseCallbackHandler that intercepts tool calls for governance.

    Captures pre-execution (on_tool_start) and post-execution (on_tool_end)
    events, computing input/output hashes, latency, and risk flags.

    All events are logged as structured JSON via Loguru with fields matching
    the AgentEvent Pydantic schema.

    Attributes:
        config: Interceptor configuration (agent_id, session_id, thresholds).
        events: Dict mapping run_id to in-flight AgentEvent instances.
        completed_events: List of finalized events (append-only).
    """

    def __init__(
        self,
        agent_id: str = "default-agent",
        session_id: str = "default-session",
        config: InterceptorConfig | None = None,
        event_queue: EventQueue | None = None,
        db_path: str | None = None,
        policy_path: str | None = None,
        dlp_sensitivity: str | None = None,
        injection_sensitivity: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the AgentGuard interceptor.

        Args:
            agent_id: Identifier for the agent being monitored.
            session_id: Session identifier for event grouping.
            config: Optional full configuration. If provided, agent_id and
                session_id parameters are ignored in favor of config values.
            event_queue: Optional pre-configured EventQueue for non-blocking
                persistence. If None and db_path is provided, a queue+store
                is auto-created and started.
            db_path: Path to SQLite database. If provided without event_queue,
                creates an EventStore + EventQueue automatically.
            policy_path: Path to YAML policy file. If provided, creates a
                PolicyEngine and evaluates every tool call against the rules.
            dlp_sensitivity: DLP scanning level (LOW | MEDIUM | HIGH).
                If provided, creates a DLPScanner and scans inputs/outputs.
            **kwargs: Additional arguments passed to BaseCallbackHandler.
        """
        super().__init__(**kwargs)
        if config is not None:
            self.config = config
        else:
            self.config = InterceptorConfig(agent_id=agent_id, session_id=session_id)

        self.events: dict[UUID, AgentEvent] = {}
        self.completed_events: list[AgentEvent] = []
        self._start_times: dict[UUID, float] = {}
        self._call_timestamps: deque[float] = deque()

        # Set up non-blocking event queue
        if event_queue is not None:
            self._event_queue = event_queue
        elif db_path is not None:
            store = EventStore(db_path=db_path)
            self._event_queue = EventQueue(store=store)
            self._event_queue.start()
        else:
            self._event_queue = None

        # Set up policy engine
        if policy_path is not None:
            self._policy_engine = PolicyEngine(policy_path)
        else:
            self._policy_engine = None

        # Set up DLP scanner
        if dlp_sensitivity is not None:
            self._dlp_scanner = DLPScanner(sensitivity=dlp_sensitivity)
        else:
            self._dlp_scanner = None

        # Set up injection detector
        if injection_sensitivity is not None:
            self._injection_detector = InjectionDetector(
                sensitivity=injection_sensitivity
            )
        else:
            self._injection_detector = None

    @property
    def agent_id(self) -> str:
        """Return the configured agent ID."""
        return self.config.agent_id

    @property
    def session_id(self) -> str:
        """Return the configured session ID."""
        return self.config.session_id

    @property
    def policy_engine(self) -> PolicyEngine | None:
        """Return the configured policy engine, if any."""
        return self._policy_engine

    @property
    def event_queue(self) -> EventQueue | None:
        """Return the configured event queue, if any."""
        return self._event_queue

    def _enqueue_event(self, event: AgentEvent) -> None:
        """Enqueue a completed event for non-blocking persistence.

        If an event queue is configured, the event is put on the queue
        and this method returns immediately (<5ms). If no queue is
        configured, this is a no-op — events remain in completed_events.
        """
        if self._event_queue is not None:
            self._event_queue.enqueue(event)

    def _log_event(self, event: AgentEvent, phase: str) -> None:
        """Emit a structured JSON log entry for an event.

        Logs the full AgentEvent as structured key-value pairs so Loguru's
        serialize=True produces machine-readable JSON output.

        Args:
            event: The AgentEvent to log.
            phase: The lifecycle phase ("tool_start", "tool_end", "tool_error").
        """
        logger.bind(
            phase=phase,
            event_id=str(event.event_id),
            timestamp=event.timestamp.isoformat(),
            agent_id=event.agent_id,
            session_id=event.session_id,
            tool_name=event.tool_name,
            run_id=str(event.run_id),
            parent_run_id=str(event.parent_run_id) if event.parent_run_id else None,
            input_hash=event.input_hash,
            output_hash=event.output_hash,
            latency_ms=event.latency_ms,
            risk_flags=event.risk_flags,
            policy_result=event.policy_result,
            completed=event.completed,
        ).info(
            "agentguard.{phase} | tool={tool} agent={agent} policy={policy}",
            phase=phase,
            tool=event.tool_name,
            agent=event.agent_id,
            policy=event.policy_result,
        )

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Capture pre-execution event when a tool call begins.

        Creates an AgentEvent with input metadata, computes the input hash,
        and stores the start time for latency calculation.

        This method is fail-open: any exception is caught and logged as a
        WARNING — the tool call always proceeds.

        Args:
            serialized: Serialized tool definition from LangChain.
            input_str: Raw input string passed to the tool.
            run_id: Unique run ID for this tool invocation.
            parent_run_id: Run ID of the parent (agent) invocation.
            tags: Optional tags from LangChain.
            metadata: Optional metadata from LangChain.
            inputs: Optional structured inputs dict.
            **kwargs: Additional callback arguments.
        """
        try:
            tool_name = serialized.get("name", "")
            if not tool_name:
                id_field = serialized.get("id")
                tool_name = (
                    id_field[-1]
                    if isinstance(id_field, list) and id_field
                    else "unknown_tool"
                )

            event = AgentEvent(
                agent_id=self.config.agent_id,
                session_id=self.config.session_id,
                tool_name=tool_name,
                run_id=run_id,
                parent_run_id=parent_run_id,
                input_str=input_str,
                input_hash=AgentEvent.compute_hash(input_str),
            )

            # Check unknown tool
            if self._is_unknown_tool(tool_name):
                event.risk_flags.append(RiskFlag.UNKNOWN_TOOL)

            # Auto-flag risks on input
            input_flags = self._detect_input_risks(input_str)
            event.risk_flags.extend(input_flags)

            # DLP scan on input (if scanner configured)
            if self._dlp_scanner is not None:
                dlp_result = self._dlp_scanner.scan(input_str, direction="input")
                if (
                    dlp_result.entity_count > 0
                    and RiskFlag.PII_DETECTED not in event.risk_flags
                ):
                    event.risk_flags.append(RiskFlag.PII_DETECTED)

            # Injection scan on input (if detector configured)
            if self._injection_detector is not None:
                inj_result = self._injection_detector.scan(input_str)
                if inj_result.status == "INJECTED":
                    event.policy_result = "BLOCK"
                elif (
                    inj_result.status == "SUSPICIOUS"
                    and event.policy_result == "PENDING"
                ):
                    event.policy_result = "ALERT"

            # Policy evaluation (if engine configured)
            if self._policy_engine is not None:
                decision = self._policy_engine.evaluate(event)
                event.policy_result = decision.result

            self.events[run_id] = event
            self._start_times[run_id] = time.perf_counter()

            # Track call frequency
            now = time.time()
            self._call_timestamps.append(now)

            # Structured JSON log
            self._log_event(event, "tool_start")

        except Exception as e:
            logger.opt(exception=True).warning(
                "AgentGuard interceptor error in on_tool_start (fail-open): {error}",
                error=str(e),
            )

    def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Capture post-execution event when a tool call completes.

        Finalizes the AgentEvent with output data, computes latency, and
        runs output risk detection.

        This method is fail-open: any exception is caught and logged as a
        WARNING — the result is always returned to the agent.

        Args:
            output: Raw output string returned by the tool.
            run_id: Unique run ID matching the on_tool_start call.
            parent_run_id: Run ID of the parent (agent) invocation.
            tags: Optional tags from LangChain.
            **kwargs: Additional callback arguments.
        """
        try:
            output_text = str(output)

            event = self.events.get(run_id)
            if event is None:
                logger.warning(
                    "on_tool_end called for unknown run_id={run_id} (no matching on_tool_start)",
                    run_id=str(run_id),
                )
                return

            # Calculate latency
            start_time = self._start_times.pop(run_id, None)
            latency_ms = (
                (time.perf_counter() - start_time) * 1000
                if start_time is not None
                else 0.0
            )

            # Finalize the event
            event.finalize(output=output_text, latency_ms=latency_ms)

            # Auto-flag risks on output
            output_flags = self._detect_output_risks(output_text)
            for flag in output_flags:
                if flag not in event.risk_flags:
                    event.risk_flags.append(flag)

            # DLP scan on output (if scanner configured)
            if self._dlp_scanner is not None:
                dlp_result = self._dlp_scanner.scan(output_text, direction="output")
                if (
                    dlp_result.entity_count > 0
                    and RiskFlag.PII_DETECTED not in event.risk_flags
                ):
                    event.risk_flags.append(RiskFlag.PII_DETECTED)

            # Check high-frequency
            if (
                self._is_high_frequency()
                and RiskFlag.HIGH_FREQUENCY not in event.risk_flags
            ):
                event.risk_flags.append(RiskFlag.HIGH_FREQUENCY)

            # If no policy module has evaluated yet, default to ALLOW
            if event.policy_result == "PENDING":
                event.policy_result = "ALLOW"

            # Move from in-flight to completed
            self.events.pop(run_id, None)
            self.completed_events.append(event)

            # Non-blocking enqueue for persistence
            self._enqueue_event(event)

            # Structured JSON log
            self._log_event(event, "tool_end")

        except Exception as e:
            logger.opt(exception=True).warning(
                "AgentGuard interceptor error in on_tool_end (fail-open): {error}",
                error=str(e),
            )

    def on_tool_error(
        self,
        error: BaseException,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        tags: list[str] | None = None,
        **kwargs: Any,
    ) -> None:
        """Handle tool execution errors gracefully.

        Records the error in the event and moves it to completed_events
        so the error is captured in the audit trail.

        Args:
            error: The exception raised by the tool.
            run_id: Unique run ID matching the on_tool_start call.
            parent_run_id: Run ID of the parent (agent) invocation.
            tags: Optional tags from LangChain.
            **kwargs: Additional callback arguments.
        """
        try:
            event = self.events.pop(run_id, None)
            if event is None:
                return

            start_time = self._start_times.pop(run_id, None)
            latency_ms = (
                (time.perf_counter() - start_time) * 1000
                if start_time is not None
                else 0.0
            )

            error_output = f"TOOL_ERROR: {type(error).__name__}: {error}"
            event.finalize(output=error_output, latency_ms=latency_ms)
            event.policy_result = "ALLOW"

            self.completed_events.append(event)

            # Non-blocking enqueue for persistence
            self._enqueue_event(event)

            # Structured JSON log
            self._log_event(event, "tool_error")

        except Exception as e:
            logger.opt(exception=True).warning(
                "AgentGuard interceptor error in on_tool_error (fail-open): {error}",
                error=str(e),
            )

    # ── Risk Detection ────────────────────────────────────────────────

    def _detect_input_risks(self, input_str: str) -> list[RiskFlag]:
        """Detect risk flags on tool input.

        Checks for sensitive keywords and external domains.

        Args:
            input_str: The raw input string to scan.

        Returns:
            List of detected risk flags.
        """
        flags: list[RiskFlag] = []

        # Sensitive keywords
        lower_input = input_str.lower()
        if any(kw in lower_input for kw in self.config.sensitive_keywords):
            flags.append(RiskFlag.SENSITIVE_KEYWORD)

        # External domain (not in internal allowlist)
        if self._has_external_domain(input_str):
            flags.append(RiskFlag.EXTERNAL_DOMAIN)

        return flags

    def _detect_output_risks(self, output_str: str) -> list[RiskFlag]:
        """Detect risk flags on tool output.

        Checks for large payloads, sensitive keywords, and external domains.

        Args:
            output_str: The raw output string to scan.

        Returns:
            List of detected risk flags.
        """
        flags: list[RiskFlag] = []

        # Large payload (output > threshold)
        if len(output_str.encode("utf-8")) > self.config.large_payload_threshold_bytes:
            flags.append(RiskFlag.LARGE_PAYLOAD)

        # Sensitive keywords
        lower_output = output_str.lower()
        if (
            any(kw in lower_output for kw in self.config.sensitive_keywords)
            and RiskFlag.SENSITIVE_KEYWORD not in flags
        ):
            flags.append(RiskFlag.SENSITIVE_KEYWORD)

        # External domain (not in internal allowlist)
        if (
            self._has_external_domain(output_str)
            and RiskFlag.EXTERNAL_DOMAIN not in flags
        ):
            flags.append(RiskFlag.EXTERNAL_DOMAIN)

        return flags

    def _has_external_domain(self, text: str) -> bool:
        """Check if text contains URLs pointing to non-internal domains.

        If internal_domains is configured, a URL is external only if its
        domain does not match any entry in the allowlist. If internal_domains
        is empty, any URL is considered external.

        Args:
            text: The text to scan for URLs.

        Returns:
            True if at least one external domain URL is found.
        """
        urls = re.findall(r"https?://([^\s/\"'<>]+)", text, re.IGNORECASE)
        if not urls:
            return False

        allowlist = self.config.internal_domains
        if not allowlist:
            # No allowlist configured — any URL is external
            return True

        for domain in urls:
            domain_lower = domain.lower()
            if not any(
                domain_lower == d or domain_lower.endswith("." + d) for d in allowlist
            ):
                return True

        return False

    def _is_unknown_tool(self, tool_name: str) -> bool:
        """Check if a tool is not in the known-good allowlist.

        If known_tools is empty, unknown_tool detection is disabled
        (returns False for all tools).

        Args:
            tool_name: Name of the tool to check.

        Returns:
            True if the tool is not in the known-good list.
        """
        if not self.config.known_tools:
            return False
        return tool_name not in self.config.known_tools

    def _is_high_frequency(self) -> bool:
        """Check if tool calls exceed the high-frequency threshold.

        Counts calls within the configured time window and compares
        against the threshold.

        Returns:
            True if the number of calls in the window exceeds the threshold.
        """
        now = time.time()
        cutoff = now - self.config.high_frequency_window_seconds

        # Prune old timestamps
        while self._call_timestamps and self._call_timestamps[0] < cutoff:
            self._call_timestamps.popleft()

        return len(self._call_timestamps) > self.config.high_frequency_threshold

    # ── Public API ────────────────────────────────────────────────────

    def get_events(self) -> list[AgentEvent]:
        """Return a copy of all completed events.

        Returns:
            List of finalized AgentEvent instances.
        """
        return list(self.completed_events)

    def get_event_count(self) -> int:
        """Return the total number of completed events.

        Returns:
            Number of completed events.
        """
        return len(self.completed_events)

    def clear_events(self) -> None:
        """Clear all completed events.

        Useful for testing or when events have been flushed to the event store.
        """
        self.completed_events.clear()

    def health_check(self) -> dict[str, Any]:
        """Return JSON-serializable health status for monitoring.

        Designed for load balancers and monitoring systems. Returns
        the current state of the interceptor, event queue, and store.

        Returns:
            Dict with keys: status, version, agent_id, session_id,
            db_connection, queue_depth, events_written, events_dropped,
            events_in_memory, events_per_second.
        """
        from agentguard import __version__

        health: dict[str, Any] = {
            "status": "healthy",
            "version": __version__,
            "agent_id": self.config.agent_id,
            "session_id": self.config.session_id,
            "events_in_memory": len(self.completed_events),
            "inflight_events": len(self.events),
        }

        # Queue metrics
        if self._event_queue is not None:
            health["queue_depth"] = self._event_queue.queue_depth
            health["events_written"] = self._event_queue.events_written
            health["events_dropped"] = self._event_queue.events_dropped

            # Events per second (rolling window from call timestamps)
            now = time.time()
            cutoff = now - 60
            recent = sum(1 for ts in self._call_timestamps if ts >= cutoff)
            elapsed = (
                min(60.0, now - self._call_timestamps[0])
                if self._call_timestamps
                else 60.0
            )
            health["events_per_second"] = round(recent / max(elapsed, 0.001), 2)

            # DB connection status from store
            try:
                store_health = self._event_queue.store.health_check()
                health["db_connection"] = store_health.get("status", "unknown")
                health["db_event_count"] = store_health.get("event_count", 0)
            except Exception:
                health["db_connection"] = "unhealthy"
                health["status"] = "degraded"
        else:
            health["queue_depth"] = 0
            health["events_written"] = 0
            health["events_dropped"] = 0
            health["events_per_second"] = 0.0
            health["db_connection"] = "not_configured"

        return health
