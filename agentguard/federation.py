"""Multi-agent federation: distributed session tracking and cross-agent governance.

Tracks agent interactions across distributed multi-agent systems using
W3C TraceContext-inspired session propagation. A single AgentGuard
instance can govern multiple agent deployments with federation policies
controlling which agents can call which other agents.

Key concepts:
  - TraceSession: distributed session spanning multiple agents
  - AgentNode: a registered agent in the federation graph
  - FederationPolicy: rules for inter-agent communication
  - CallGraph: directed graph of agent-to-agent tool calls

Usage:
    from agentguard.federation import FederationManager

    fm = FederationManager()
    fm.register_agent("email-agent", cluster="us-east")
    fm.register_agent("crm-agent", cluster="us-east")

    session = fm.create_session(initiator="email-agent")
    fm.record_handoff(session.trace_id, from_agent="email-agent", to_agent="crm-agent")

    graph = fm.get_call_graph(session.trace_id)
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from agentguard.logging import logger

# ── Models ───────────────────────────────────────────────────────────


class AgentNode(BaseModel):
    """A registered agent in the federation."""

    agent_id: str = Field(description="Unique agent identifier")
    cluster: str = Field(default="default", description="Deployment cluster name")
    tools: list[str] = Field(
        default_factory=list, description="Tools this agent can call"
    )
    registered_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    metadata: dict[str, Any] = Field(default_factory=dict)


class TraceSession(BaseModel):
    """A distributed session spanning multiple agents (W3C TraceContext-inspired)."""

    trace_id: str = Field(
        default_factory=lambda: uuid4().hex,
        description="Globally unique trace ID (32-char hex)",
    )
    parent_id: str | None = Field(
        default=None, description="Parent span ID for nested sessions"
    )
    initiator: str = Field(description="Agent that started this session")
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    agents_involved: list[str] = Field(default_factory=list)
    handoffs: list[dict[str, Any]] = Field(default_factory=list)
    status: str = Field(default="active", description="active | completed | failed")


class Handoff(BaseModel):
    """A single agent-to-agent handoff within a session."""

    from_agent: str
    to_agent: str
    tool_name: str = Field(default="")
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    latency_ms: float = Field(default=0.0)
    policy_result: str = Field(default="ALLOW")


class FederationRule(BaseModel):
    """Policy rule for inter-agent communication."""

    id: str = Field(description="Rule identifier")
    from_agent: str = Field(description="Source agent pattern (exact or '*' wildcard)")
    to_agent: str = Field(description="Destination agent pattern")
    action: str = Field(default="ALLOW", description="ALLOW | BLOCK | ALERT")
    conditions: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional conditions (cluster, tool_name, etc.)",
    )


# ── Manager ──────────────────────────────────────────────────────────


class FederationManager:
    """Manages multi-agent federation, session tracking, and cross-agent policies.

    Attributes:
        agents: Registry of known agents.
        sessions: Active and completed trace sessions.
        rules: Federation policy rules.
    """

    def __init__(self) -> None:
        self._agents: dict[str, AgentNode] = {}
        self._sessions: dict[str, TraceSession] = {}
        self._rules: list[FederationRule] = []

    # ── Agent Registry ───────────────────────────────────────────

    def register_agent(
        self,
        agent_id: str,
        cluster: str = "default",
        tools: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentNode:
        """Register an agent in the federation."""
        node = AgentNode(
            agent_id=agent_id,
            cluster=cluster,
            tools=tools or [],
            metadata=metadata or {},
        )
        self._agents[agent_id] = node
        logger.bind(module="agentguard.federation").info(
            "Agent registered: {agent} (cluster={cluster})",
            agent=agent_id,
            cluster=cluster,
        )
        return node

    def get_agent(self, agent_id: str) -> AgentNode | None:
        return self._agents.get(agent_id)

    def list_agents(self) -> list[AgentNode]:
        return list(self._agents.values())

    # ── Session Tracking ─────────────────────────────────────────

    def create_session(
        self, initiator: str, parent_id: str | None = None
    ) -> TraceSession:
        """Create a new distributed trace session."""
        session = TraceSession(
            initiator=initiator,
            parent_id=parent_id,
            agents_involved=[initiator],
        )
        self._sessions[session.trace_id] = session
        logger.bind(module="agentguard.federation").info(
            "Session created: {trace_id} (initiator={initiator})",
            trace_id=session.trace_id,
            initiator=initiator,
        )
        return session

    def get_session(self, trace_id: str) -> TraceSession | None:
        return self._sessions.get(trace_id)

    def list_sessions(self, status: str | None = None) -> list[TraceSession]:
        sessions = list(self._sessions.values())
        if status:
            sessions = [s for s in sessions if s.status == status]
        return sessions

    def complete_session(self, trace_id: str) -> bool:
        session = self._sessions.get(trace_id)
        if session is None:
            return False
        session.status = "completed"
        return True

    # ── Handoff Tracking ─────────────────────────────────────────

    def record_handoff(
        self,
        trace_id: str,
        from_agent: str,
        to_agent: str,
        tool_name: str = "",
        latency_ms: float = 0.0,
    ) -> Handoff | None:
        """Record an agent-to-agent handoff within a session.

        Evaluates federation policies before recording. Returns the
        handoff record, or None if the session doesn't exist.
        """
        session = self._sessions.get(trace_id)
        if session is None:
            return None

        # Evaluate federation policy
        policy_result = self.evaluate_federation(from_agent, to_agent, tool_name)

        handoff = Handoff(
            from_agent=from_agent,
            to_agent=to_agent,
            tool_name=tool_name,
            latency_ms=latency_ms,
            policy_result=policy_result,
        )

        session.handoffs.append(handoff.model_dump())
        if to_agent not in session.agents_involved:
            session.agents_involved.append(to_agent)

        logger.bind(module="agentguard.federation").info(
            "Handoff: {from_a} → {to_a} (trace={trace}, policy={policy})",
            from_a=from_agent,
            to_a=to_agent,
            trace=trace_id[:8],
            policy=policy_result,
        )

        return handoff

    # ── Call Graph ───────────────────────────────────────────────

    def get_call_graph(self, trace_id: str) -> dict[str, Any] | None:
        """Get the directed call graph for a session.

        Returns a dict with nodes (agents) and edges (handoffs).
        """
        session = self._sessions.get(trace_id)
        if session is None:
            return None

        nodes = [
            {
                "id": aid,
                "cluster": (
                    self._agents[aid].cluster if aid in self._agents else "unknown"
                ),
            }
            for aid in session.agents_involved
        ]

        edges = [
            {
                "from": h["from_agent"],
                "to": h["to_agent"],
                "tool": h.get("tool_name", ""),
                "policy": h.get("policy_result", "ALLOW"),
                "timestamp": h.get("timestamp", ""),
            }
            for h in session.handoffs
        ]

        return {
            "trace_id": trace_id,
            "status": session.status,
            "initiator": session.initiator,
            "nodes": nodes,
            "edges": edges,
            "agent_count": len(nodes),
            "handoff_count": len(edges),
        }

    # ── Federation Policy ────────────────────────────────────────

    def add_rule(self, rule: FederationRule) -> None:
        """Add a federation policy rule."""
        self._rules.append(rule)

    def set_rules(self, rules: list[FederationRule]) -> None:
        """Replace all federation rules."""
        self._rules = list(rules)

    def evaluate_federation(
        self, from_agent: str, to_agent: str, tool_name: str = ""
    ) -> str:
        """Evaluate federation policy for an inter-agent call.

        Returns "ALLOW", "BLOCK", or "ALERT".
        """
        for rule in self._rules:
            from_match = rule.from_agent == "*" or rule.from_agent == from_agent
            to_match = rule.to_agent == "*" or rule.to_agent == to_agent

            if from_match and to_match:
                # Check additional conditions
                cond_tool = rule.conditions.get("tool_name")
                if cond_tool and cond_tool != tool_name:
                    continue
                return rule.action

        return "ALLOW"  # Default allow if no rule matches

    # ── Stats ────────────────────────────────────────────────────

    def stats(self) -> dict[str, Any]:
        """Return federation statistics."""
        return {
            "registered_agents": len(self._agents),
            "active_sessions": len(
                [s for s in self._sessions.values() if s.status == "active"]
            ),
            "completed_sessions": len(
                [s for s in self._sessions.values() if s.status == "completed"]
            ),
            "total_handoffs": sum(len(s.handoffs) for s in self._sessions.values()),
            "federation_rules": len(self._rules),
        }
