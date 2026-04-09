# agentguard/ — Python Core Library

## Overview

This is the main Python package providing AI agent governance. All security modules live here.

## Module Map

| Module | Purpose | Sprint | PRD Refs |
|--------|---------|--------|----------|
| `interceptor.py` | LangGraph BaseCallbackHandler — intercepts on_tool_start/on_tool_end | 2 | AM-01 to AM-09 |
| `event_store.py` | Append-only SQLite event store + SHA-256 audit chain | 2, 4 | AC-01 to AC-06 |
| `policy_engine.py` | YAML policy rule loader and evaluator | 3 | PE-01 to PE-07 |
| `dlp_scanner.py` | Microsoft Presidio PII detection (100% local) | 3 | DLP-01 to DLP-06 |
| `injection_detector.py` | Two-stage prompt injection detection (regex + LLM) | 4 | PI-01 to PI-06 |
| `llm_client.py` | Provider-agnostic LLM abstraction (Ollama/OpenAI/Anthropic) | 4 | - |
| `models.py` | Pydantic v2 data models shared across modules | All | - |

## Coding Rules

- **Pydantic v2** for all data models (not v1, not dataclasses)
- **Type hints** on every function signature and return type
- **Loguru** for structured JSON logging (not stdlib logging)
- **UUID4** for all event IDs
- **ISO 8601** for all timestamps
- **SHA-256** via `hashlib` for all hashing (input_hash, output_hash, event_hash)
- **asyncio.Queue** for non-blocking event writes (tool calls must not wait for DB)

## Fail-Open Pattern (CRITICAL)

Every method in the interceptor pipeline MUST follow this pattern:

```python
def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id, **kwargs):
    try:
        # Policy evaluation, DLP scan, injection detection
        ...
    except Exception as e:
        logger.warning(f"AgentGuard interceptor error (fail-open): {e}")
        # NEVER re-raise — the tool call MUST proceed
```

The agent's tool call is NEVER blocked due to AgentGuard's own errors. Only explicit policy BLOCK decisions prevent tool execution.

## Interceptor Pipeline Order

```
on_tool_start:
  1. Create AgentEvent with metadata (agent_id, tool_name, input_hash, etc.)
  2. Run DLP scan on input text
  3. Run injection detection on input text
  4. Evaluate policy engine (conditions include DLP + injection results)
  5. If policy result = BLOCK → raise AgentGuardBlockException
  6. Enqueue event to async write queue

on_tool_end:
  1. Record output_hash, latency_ms
  2. Run DLP scan on output text
  3. Auto-flag risks (external_domain, large_payload, sensitive_keyword, high_frequency)
  4. Enqueue completed event to async write queue
```

## Performance Targets

| Operation | p50 | p95 | p99 |
|-----------|-----|-----|-----|
| Interceptor overhead | <5ms | <20ms | <50ms |
| Policy evaluation | <1ms | <3ms | <5ms |
| DLP scan (10KB) | - | - | <50ms |
| Queue write | - | - | <5ms |
| Regex injection scan (1KB) | - | - | <5ms |

## Dependencies (to be added to pyproject.toml)

```
langchain-core          # BaseCallbackHandler
langgraph               # Agent framework integration
pydantic>=2.0           # Data models
pyyaml                  # Policy YAML parsing
presidio-analyzer       # DLP PII detection
presidio-anonymizer     # DLP PII redaction
loguru                  # Structured logging
httpx                   # Async HTTP (LLM client)
```
