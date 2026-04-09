# agentguard/ — Core Python Package

The main AgentGuard library providing AI agent governance.

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| `interceptor.py` | Stub | LangGraph `BaseCallbackHandler` — intercepts `on_tool_start` / `on_tool_end` |
| `policy_engine.py` | Stub | YAML policy rule loader and evaluator (ALLOW / BLOCK / ALERT / BYPASS) |
| `dlp_scanner.py` | Stub | Microsoft Presidio PII detection — 15+ entity types, 100% local |
| `injection_detector.py` | Stub | Two-stage prompt injection detection (regex + LLM classifier) |
| `event_store.py` | Stub | Append-only SQLite event store with SHA-256 audit chain |
| `llm_client.py` | Stub | Provider-agnostic LLM abstraction (Ollama / OpenAI / Anthropic) |
| `models.py` | Stub | Pydantic v2 data models shared across modules |

## Key Design Decisions

- **Fail-open**: Interceptor exceptions are caught and logged — never block the agent
- **Non-blocking**: Async queue ensures tool calls don't wait for DB I/O (<5ms p99)
- **Local-first DLP**: All PII scanning runs locally via Presidio, zero data egress
- **Pydantic v2**: All data models use Pydantic v2 (not v1, not dataclasses)

## Usage

```python
from agentguard import AgentGuardInterceptor

config = {"callbacks": [AgentGuardInterceptor()]}
agent.invoke(input, config=config)
```
