"""AgentGuard - Guardrails and policy enforcement for AI agents."""

__version__ = "0.1.0"

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
    "InterceptorConfig",
    "PolicyResult",
    "RiskFlag",
]
