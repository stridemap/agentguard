"""AgentGuard - Guardrails and policy enforcement for AI agents."""

__version__ = "2.0.0"

from agentguard.dlp_scanner import DLPConfig, DLPResult, DLPScanner
from agentguard.event_store import EventQueue, EventStore
from agentguard.injection_detector import InjectionDetector, InjectionResult
from agentguard.interceptor import AgentGuardInterceptor
from agentguard.llm_client import LLMClient, MockLLMClient, get_llm_client
from agentguard.models import (
    AgentEvent,
    AlertSeverity,
    InterceptorConfig,
    PolicyResult,
    RiskFlag,
)
from agentguard.policy_engine import PolicyDecision, PolicyEngine, PolicyValidationError

__all__ = [
    "AgentGuardInterceptor",
    "AgentEvent",
    "AlertSeverity",
    "DLPConfig",
    "DLPResult",
    "DLPScanner",
    "EventQueue",
    "EventStore",
    "InjectionDetector",
    "InjectionResult",
    "InterceptorConfig",
    "LLMClient",
    "MockLLMClient",
    "PolicyDecision",
    "PolicyEngine",
    "PolicyResult",
    "PolicyValidationError",
    "RiskFlag",
    "get_llm_client",
]
