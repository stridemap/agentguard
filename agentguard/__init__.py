"""AgentGuard - Guardrails and policy enforcement for AI agents."""

__version__ = "0.1.0"

from agentguard.event_store import EventQueue, EventStore
from agentguard.interceptor import AgentGuardInterceptor
from agentguard.models import (
    AgentEvent,
    AlertSeverity,
    InterceptorConfig,
    PolicyResult,
    RiskFlag,
)

__all__ = [
    "AgentGuardInterceptor",
    "AgentEvent",
    "AlertSeverity",
    "EventQueue",
    "EventStore",
    "InterceptorConfig",
    "PolicyResult",
    "RiskFlag",
]
